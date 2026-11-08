import unittest

from aion_adapter.resource_permission_guard import (
    VALID,
    INVALID,
    INDETERMINATE,
    validate_resource_permission,
)


TEAM = "000000000000000000000002"
MEMBER = "000000000000000000000011"
RESOURCE = "000000000000000000000050"

CATALOG = [{
    "name": "deploy",
    "type": "project",
    "available": True,
    "availableForRBAC": True,
    "availableForDAC": True,
}]

ASSIGNMENT = {
    "_id": "000000000000000000000040",
    "name": "deploy",
    "type": "project",
    "team": TEAM,
    "member": {
        "_id": MEMBER,
        "team": TEAM,
        "user": {"fullname": "Synthetic User"},
        "role": "000000000000000000000022",
    },
    "project": {
        "_id": RESOURCE,
        "project_id": "synthetic-app",
    },
}


def check(catalog=CATALOG, assignments=None, **overrides):
    values = {
        "expected_team_id": TEAM,
        "expected_member_id": MEMBER,
        "permission_type": "project",
        "permission_name": "deploy",
        "resource_id": RESOURCE,
    }
    values.update(overrides)

    if assignments is None:
        assignments = [ASSIGNMENT]

    return validate_resource_permission(
        catalog,
        assignments,
        **values,
    )


class ResourcePermissionGuardTests(unittest.TestCase):

    def test_valid_assignment(self):
        self.assertEqual(check(), VALID)

    def test_wrong_member(self):
        self.assertEqual(
            check(expected_member_id="000000000000000000000099"),
            INVALID,
        )

    def test_wrong_team(self):
        self.assertEqual(
            check(expected_team_id="000000000000000000000099"),
            INVALID,
        )

    def test_wrong_resource(self):
        self.assertEqual(
            check(resource_id="000000000000000000000099"),
            INVALID,
        )

    def test_dac_unavailable(self):
        catalog = [dict(CATALOG[0], availableForDAC=False)]
        self.assertEqual(check(catalog=catalog), INVALID)

    def test_permission_unavailable(self):
        catalog = [dict(CATALOG[0], available=False)]
        self.assertEqual(check(catalog=catalog), INVALID)

    def test_assignment_missing(self):
        self.assertEqual(check(assignments=[]), INVALID)

    def test_missing_catalog(self):
        self.assertEqual(check(catalog=None), INDETERMINATE)

    def test_malformed_assignment(self):
        self.assertEqual(check(assignments=[{}]), INDETERMINATE)

    def test_duplicate_assignment(self):
        self.assertEqual(
            check(assignments=[ASSIGNMENT, ASSIGNMENT]),
            INDETERMINATE,
        )

    def test_invalid_resource_id(self):
        self.assertEqual(
            check(resource_id="not-an-object-id"),
            INVALID,
        )

    def test_unknown_permission_type(self):
        self.assertEqual(
            check(permission_type="billing"),
            INVALID,
        )

    def test_non_string_permission_type(self):
        self.assertEqual(
            check(permission_type=[]),
            INVALID,
        )


if __name__ == "__main__":
    unittest.main()
