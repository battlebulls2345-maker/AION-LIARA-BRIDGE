"""AION LIARA live authentication and creator-context validator.

This module validates a read-only /v1/me response.
It never grants resource permissions or authorizes deployment.
"""

import re

from aion_adapter.liara_readonly_client import fetch_current_user
from aion_adapter.auth_guard import validate_team_context
from aion_adapter.identity_binding_guard import validate_creator_identity

POLICY_VERSION = "AION_LIARA_LIVE_AUTH_VALIDATOR_V01"

VALID = "VALIDATED_CREATOR_CONTEXT"
INVALID = "INVALID"
INDETERMINATE = "INDETERMINATE"

OBJECT_ID = re.compile(r"^[0-9a-fA-F]{24}$")


def _result(status, decision, stages, http_status=None):
    result = {
        "policy_version": POLICY_VERSION,
        "status": status,
        "decision": decision,
        "stages": stages,
        "payload_exposed": False,
        "permissions_granted": False,
        "deployment_authorized": False,
    }
    if isinstance(http_status, int):
        result["http_status"] = http_status
    return result


def validate_live_context(
    token,
    expected_team_id,
    expected_user_id,
    transport=None,
):
    """Validate a LIARA creator context using a single read-only GET."""

    stages = {
        "transport": "NOT_STARTED",
        "authentication": "NOT_STARTED",
        "team_context": "NOT_STARTED",
        "identity_binding": "NOT_STARTED",
    }

    if (
        not isinstance(expected_team_id, str)
        or not OBJECT_ID.fullmatch(expected_team_id)
        or not isinstance(expected_user_id, str)
        or not OBJECT_ID.fullmatch(expected_user_id)
    ):
        stages["identity_binding"] = INVALID
        return _result(INVALID, "DENY", stages)

    try:
        response = fetch_current_user(
            token,
            team_id=expected_team_id,
            transport=transport,
        )
    except Exception:
        stages["transport"] = INDETERMINATE
        return _result(INDETERMINATE, "DENY", stages)

    response_status = response.get("status")
    http_status = response.get("http_status")

    if response_status != "TRANSPORT_OK_UNVALIDATED":
        stages["transport"] = response_status or INDETERMINATE

        if response_status == "AUTH_REJECTED":
            stages["authentication"] = INVALID
            return _result(INVALID, "DENY", stages, http_status)

        return _result(INDETERMINATE, "DENY", stages, http_status)

    stages["transport"] = "TLS_HTTP_RESPONSE_OK"
    stages["authentication"] = "TOKEN_ACCEPTED_BY_API"

    payload = response.get("payload")

    team_result = validate_team_context(payload, expected_team_id)
    stages["team_context"] = team_result

    if team_result != "VALID_CONTEXT":
        decision_status = (
            INVALID if team_result == INVALID else INDETERMINATE
        )
        return _result(decision_status, "DENY", stages, http_status)

    identity_result = validate_creator_identity(
        payload,
        expected_team_id,
        expected_user_id,
    )
    stages["identity_binding"] = identity_result

    if identity_result != "VALID_CREATOR_IDENTITY":
        decision_status = (
            INVALID if identity_result == INVALID else INDETERMINATE
        )
        return _result(decision_status, "DENY", stages, http_status)

    return _result(
        VALID,
        "CONTINUE_READ_ONLY_POLICY",
        stages,
        http_status,
    )
