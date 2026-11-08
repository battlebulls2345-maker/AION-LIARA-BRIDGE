import unittest

from aion_adapter.auth_guard import (
    validate_team_context,
    VALID,
    INVALID,
    INDETERMINATE,
)

TEAM_ID = "000000000000000000000002"


def valid_payload():
    return {
        "user": {
            "_id": "synthetic-user-001",
            "isVerified": True,
        },
        "team": {
            "_id": TEAM_ID,
            "joined_at": "2026-01-01T10:00:00Z",
            "teamMemberRole": {
                "name": "Viewer",
                "permissions": ["vm.read"],
            },
            "teamMemberPermissions": [],
        },
    }


class AuthGuardTests(unittest.TestCase):

    def test_valid_context(self):
        self.assertEqual(
            validate_team_context(valid_payload(), TEAM_ID), VALID
        )

    def test_team_id_mismatch(self):
        self.assertEqual(
            validate_team_context(
                valid_payload(), "111111111111111111111111"
            ),
            INVALID,
        )

    def test_unverified_account(self):
        data = valid_payload()
        data["user"]["isVerified"] = False
        self.assertEqual(
            validate_team_context(data, TEAM_ID), INVALID
        )

    def test_missing_team(self):
        data = valid_payload()
        del data["team"]
        self.assertEqual(
            validate_team_context(data, TEAM_ID), INDETERMINATE
        )

    def test_missing_role_permissions(self):
        data = valid_payload()
        del data["team"]["teamMemberRole"]["permissions"]
        self.assertEqual(
            validate_team_context(data, TEAM_ID), INDETERMINATE
        )

    def test_malformed_resource_permissions(self):
        data = valid_payload()
        data["team"]["teamMemberPermissions"] = ["unknown"]
        self.assertEqual(
            validate_team_context(data, TEAM_ID), INVALID
        )

    def test_invalid_team_id_format(self):
        self.assertEqual(
            validate_team_context(valid_payload(), "team-123"), INVALID
        )

    def test_missing_user_identity(self):
        data = valid_payload()
        del data["user"]["_id"]
        self.assertEqual(
            validate_team_context(data, TEAM_ID), INDETERMINATE
        )


if __name__ == "__main__":
    unittest.main()
