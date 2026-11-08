import re

POLICY_VERSION = "AION_LIARA_RESOURCE_PERMISSION_GUARD_V01"

VALID = "VALID"
INVALID = "INVALID"
INDETERMINATE = "INDETERMINATE"

OBJECT_ID = re.compile(r"^[0-9a-fA-F]{24}$")

RESOURCE_TYPES = {
    "project",
    "database",
    "zone",
    "bucket",
    "mailServer",
    "vm",
    "ai",
}


def _valid_id(value):
    return isinstance(value, str) and OBJECT_ID.fullmatch(value) is not None


def validate_resource_permission(
    catalog,
    assigned_permissions,
    expected_team_id,
    expected_member_id,
    permission_type,
    permission_name,
    resource_id,
):
    """
    Validates an existing LIARA DAC permission.

    This function does NOT:
    - authenticate a user;
    - prove CurrentUser._id -> Member._id mapping;
    - grant, revoke or modify permissions;
    - verify the authenticity of API responses.

    expected_member_id must come from an independently
    verified membership-to-user identity binding.
    """

    if not _valid_id(expected_team_id):
        return INVALID

    if not _valid_id(expected_member_id):
        return INVALID

    if not _valid_id(resource_id):
        return INVALID

    if not isinstance(permission_type, str):
        return INVALID

    if permission_type not in RESOURCE_TYPES:
        return INVALID

    if not isinstance(permission_name, str) or not permission_name.strip():
        return INVALID

    if not isinstance(catalog, list):
        return INDETERMINATE

    if not isinstance(assigned_permissions, list):
        return INDETERMINATE

    # Find the exact permission in the permission catalog.
    catalog_matches = []

    for item in catalog:
        if not isinstance(item, dict):
            return INDETERMINATE

        if item.get("type") == permission_type and item.get("name") == permission_name:
            catalog_matches.append(item)

    if len(catalog_matches) == 0:
        return INVALID

    if len(catalog_matches) > 1:
        return INDETERMINATE

    permission = catalog_matches[0]

    for field in ("available", "availableForDAC"):
        if not isinstance(permission.get(field), bool):
            return INDETERMINATE

    if permission["available"] is not True:
        return INVALID

    if permission["availableForDAC"] is not True:
        return INVALID

    # Validate existing assignments.
    matches = []

    for item in assigned_permissions:
        if not isinstance(item, dict):
            return INDETERMINATE

        team_id = item.get("team")
        member = item.get("member")
        item_type = item.get("type")
        item_name = item.get("name")

        if not _valid_id(team_id):
            return INDETERMINATE

        if not isinstance(member, dict):
            return INDETERMINATE

        member_id = member.get("_id")
        member_team = member.get("team")

        if not _valid_id(member_id) or not _valid_id(member_team):
            return INDETERMINATE

        if not isinstance(item_type, str) or not isinstance(item_name, str):
            return INDETERMINATE

        resource_fields = [
            key for key in RESOURCE_TYPES
            if key in item and item[key] is not None
        ]

        # LIARA documents exactly one resource object,
        # matching the permission type.
        if len(resource_fields) != 1:
            return INDETERMINATE

        actual_resource_type = resource_fields[0]
        resource = item[actual_resource_type]

        if not isinstance(resource, dict):
            return INDETERMINATE

        actual_resource_id = resource.get("_id")

        if not _valid_id(actual_resource_id):
            return INDETERMINATE

        if actual_resource_type != item_type:
            return INVALID

        if team_id != member_team:
            return INVALID

        if team_id != expected_team_id:
            continue

        if member_id != expected_member_id:
            continue

        if item_type != permission_type:
            continue

        if item_name != permission_name:
            continue

        if actual_resource_id != resource_id:
            continue

        matches.append(item)

    if len(matches) == 1:
        return VALID

    if len(matches) > 1:
        return INDETERMINATE

    return INVALID
