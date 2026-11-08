import re

POLICY_VERSION = "AION_LIARA_CREATOR_IDENTITY_BINDING_V01"

VALID_CREATOR = "VALID_CREATOR_IDENTITY"
INVALID = "INVALID"
INDETERMINATE = "INDETERMINATE"

OBJECT_ID = re.compile(r"^[0-9a-fA-F]{24}$")


def _valid_id(value):
    return isinstance(value, str) and OBJECT_ID.fullmatch(value) is not None


def validate_creator_identity(
    payload,
    expected_team_id,
    expected_user_id,
):
    """
    Validates the documented LIARA team-creator identity relationship.

    This validates response structure and identifier consistency only.
    It does NOT authenticate the API response or prove TLS/token integrity.
    It does NOT map a regular Member._id to a user ID.
    It does NOT grant permissions or authorize resource operations.
    """

    if not _valid_id(expected_team_id):
        return INVALID

    if not _valid_id(expected_user_id):
        return INVALID

    if not isinstance(payload, dict):
        return INDETERMINATE

    user = payload.get("user")
    team = payload.get("team")

    if not isinstance(user, dict) or not isinstance(team, dict):
        return INDETERMINATE

    actual_user_id = user.get("_id")
    actual_team_id = team.get("_id")
    team_creator_id = team.get("teamCreator")
    is_team_creator = user.get("isTeamCreator")
    is_team = team.get("isTeam")

    if not _valid_id(actual_user_id):
        return INDETERMINATE

    if not _valid_id(actual_team_id):
        return INDETERMINATE

    if not _valid_id(team_creator_id):
        return INDETERMINATE

    if not isinstance(is_team_creator, bool):
        return INDETERMINATE

    if not isinstance(is_team, bool):
        return INDETERMINATE

    if actual_user_id != expected_user_id:
        return INVALID

    if actual_team_id != expected_team_id:
        return INVALID

    if is_team is not True:
        return INVALID

    if is_team_creator is True:
        if team_creator_id != actual_user_id:
            return INVALID
        return VALID_CREATOR

    # A non-creator is not mapped to Member._id by this function.
    if team_creator_id == actual_user_id:
        return INVALID

    return INDETERMINATE
