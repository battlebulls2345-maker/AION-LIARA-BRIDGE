"""Minimal privacy-preserving AION evidence logger."""

import json
import os
from datetime import datetime, timezone

POLICY_VERSION = "AION_LIARA_EVIDENCE_LOGGER_V01"

ALLOWED_OUTCOMES = {
    "VALIDATED_CREATOR_CONTEXT",
    "INVALID",
    "INDETERMINATE",
}

ALLOWED_STAGE_VALUES = {
    "NOT_STARTED",
    "TLS_HTTP_RESPONSE_OK",
    "TOKEN_ACCEPTED_BY_API",
    "AUTH_REJECTED",
    "INVALID",
    "INDETERMINATE",
    "VALID_CONTEXT",
    "VALID_CREATOR_IDENTITY",
    "TRANSPORT_OK_UNVALIDATED",
    "INVALID_INPUT",
    "INVALID_TEAM_ID",
    "RATE_LIMITED",
    "REDIRECT_BLOCKED",
    "HTTP_ERROR",
}


def build_evidence(outcome, stages, http_status=None):
    if outcome not in ALLOWED_OUTCOMES:
        raise ValueError("Invalid evidence outcome")

    if not isinstance(stages, dict):
        raise ValueError("Invalid stages")

    safe_stages = {}
    for key, value in stages.items():
        if (
            not isinstance(key, str)
            or not key.replace("_", "").isalnum()
            or value not in ALLOWED_STAGE_VALUES
        ):
            raise ValueError("Invalid stage data")
        safe_stages[key] = value

    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "policy_version": POLICY_VERSION,
        "outcome": outcome,
        "stages": safe_stages,
        "http_status": http_status if isinstance(http_status, int) else None,
        "credentials_logged": False,
        "personal_data_logged": False,
        "raw_response_logged": False,
    }
    return record


def append_evidence(path, outcome, stages, http_status=None):
    record = build_evidence(outcome, stages, http_status)
    data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    flags |= getattr(os, "O_NOFOLLOW", 0)

    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)

    return {
        "status": "EVIDENCE_WRITTEN",
        "bytes": len(data),
        "credentials_logged": False,
        "personal_data_logged": False,
    }
