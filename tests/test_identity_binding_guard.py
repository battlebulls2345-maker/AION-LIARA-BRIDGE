import unittest

from aion_adapter.identity_binding_guard import (
    validate_creator_identity,
    VALID_CREATOR,
    INVALID,
    INDETERMINATE,
)

TEAM = "000000000000000000000002"
USER = "000000000000000000000011"
OTHER = "000000000000000000000099"


def payload():
    return {
        "user": {
            "_id": USER,
            "isTeamCreator": True,
        },
        "team": {
            "_id": TEAM,
            "teamCreator": USER,
            "isTeam": True,
        },
    }


def check(data=None, team_id=TEAM, user_id=USER):
    return validate_creator_identity(
        payload() if data is None else data,
        team_id,
        user_id,
    )


class IdentityBindingGuardTests(unittest.TestCase):

    def test_valid_creator_binding(self):
        self.assertEqual(check(), VALID_CREATOR)

    def test_wrong_user(self):
        self.assertEqual(check(user_id=OTHER), INVALID)

    def test_wrong_team(self):
        self.assertEqual(check(team_id=OTHER), INVALID)

    def test_creator_flag_false(self):
        data = payload()
        data["user"]["isTeamCreator"] = False
        data["team"]["teamCreator"] = OTHER
        self.assertEqual(check(data), INDETERMINATE)

    def test_creator_id_mismatch(self):
        data = payload()
        data["team"]["teamCreator"] = OTHER
        self.assertEqual(check(data), INVALID)

    def test_missing_team_creator(self):
        data = payload()
        del data["team"]["teamCreator"]
        self.assertEqual(check(data), INDETERMINATE)

    def test_malformed_payload(self):
        self.assertEqual(check([]), INDETERMINATE)

    def test_invalid_expected_user_id(self):
        self.assertEqual(check(user_id=[]), INVALID)


if __name__ == "__main__":
    unittest.main()
