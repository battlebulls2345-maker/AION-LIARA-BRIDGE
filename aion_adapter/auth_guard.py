import re

POLICY_VERSION = "AION_LIARA_AUTH_GUARD_V01"

VALID = "VALID_CONTEXT"
INVALID = "INVALID"
INDETERMINATE = "INDETERMINATE"

TEAM_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{24}$")


def validate_team_context(payload, expected_team_id):
    """
    Validates LIARA account/team response structure.
    Does NOT grant API access or verify response authenticity.
    """

    if not isinstance(payload, dict):
        return INDETERMINATE

    if not isinstance(expected_team_id, str):
        return INVALID

    if not TEAM_ID_PATTERN.fullmatch(expected_team_id):
        return INVALID

    user = payload.get("user")
    team = payload.get("team")

    if not isinstance(user, dict) or not isinstance(team, dict):
        return INDETERMINATE

    user_id = user.get("_id")
    verified = user.get("isVerified")

    if not isinstance(user_id, str) or not user_id.strip():
        return INDETERMINATE

    if verified is not True:
        return INVALID

    actual_team_id = team.get("_id")

    if not isinstance(actual_team_id, str):
        return INDETERMINATE

    if actual_team_id != expected_team_id:
        return INVALID

    joined_at = team.get("joined_at")
    role = team.get("teamMemberRole")
    resource_permissions = team.get("teamMemberPermissions")

    if not isinstance(joined_at, str) or not joined_at.strip():
        return INDETERMINATE

    if not isinstance(role, dict):
        return INDETERMINATE

    role_name = role.get("name")
    permissions = role.get("permissions")

    if not isinstance(role_name, str) or not role_name.strip():
        return INDETERMINATE

    if not isinstance(permissions, list):
        return INDETERMINATE

    if any(not isinstance(item, str) or not item.strip()
           for item in permissions):
        return INVALID

    if not isinstance(resource_permissions, list):
        return INDETERMINATE

    # A belső objektumstruktúra még nincs dokumentálva.
    if any(not isinstance(item, dict) for item in resource_permissions):
        return INVALID

    return VALID
