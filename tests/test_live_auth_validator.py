import json
import tempfile
import unittest
from pathlib import Path

from aion_adapter.live_auth_validator import (
    validate_live_context,
    VALID,
    INVALID,
    INDETERMINATE,
)
from aion_adapter.evidence_logger import (
    build_evidence,
    append_evidence,
)

TEAM_ID = "aaaaaaaaaaaaaaaaaaaaaaaa"
USER_ID = "bbbbbbbbbbbbbbbbbbbbbbbb"


def valid_payload():
    return {
        "user": {
            "_id": USER_ID,
            "isVerified": True,
            "isTeamCreator": True,
        },
        "team": {
            "_id": TEAM_ID,
            "isTeam": True,
            "teamCreator": USER_ID,
            "joined_at": "2026-01-01T00:00:00Z",
            "teamMemberRole": {
                "name": "Owner",
                "permissions": ["read"],
            },
            "teamMemberPermissions": [],
        },
    }


class FakeTransport:
    def __init__(self, status=200, payload=None):
        self.status = status
        self.payload = payload
        self.calls = 0

    def __call__(self, url, headers, timeout, max_bytes):
        self.calls += 1
        self.last_url = url
        self.last_headers = headers

        body = (
            json.dumps(self.payload).encode()
            if self.payload is not None
            else b""
        )
        return (
            self.status,
            {"Content-Type": "application/json"},
            body,
        )


class LiveAuthValidatorTests(unittest.TestCase):

    def test_valid_creator_context(self):
        transport = FakeTransport(payload=valid_payload())
        result = validate_live_context(
            "synthetic-test-token",
            TEAM_ID,
            USER_ID,
            transport,
        )
        self.assertEqual(result["status"], VALID)
        self.assertEqual(
            result["decision"],
            "CONTINUE_READ_ONLY_POLICY",
        )
        self.assertEqual(transport.calls, 1)
        self.assertFalse(result["payload_exposed"])
        self.assertFalse(result["permissions_granted"])
        self.assertFalse(result["deployment_authorized"])
        self.assertNotIn("payload", result)

    def test_token_rejected(self):
        transport = FakeTransport(status=401)
        result = validate_live_context(
            "synthetic-test-token",
            TEAM_ID,
            USER_ID,
            transport,
        )
        self.assertEqual(result["status"], INVALID)
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(transport.calls, 1)

    def test_wrong_expected_user(self):
        transport = FakeTransport(payload=valid_payload())
        result = validate_live_context(
            "synthetic-test-token",
            TEAM_ID,
            "cccccccccccccccccccccccc",
            transport,
        )
        self.assertEqual(result["status"], INVALID)
        self.assertEqual(result["decision"], "DENY")

    def test_wrong_team(self):
        transport = FakeTransport(payload=valid_payload())
        result = validate_live_context(
            "synthetic-test-token",
            "cccccccccccccccccccccccc",
            USER_ID,
            transport,
        )
        self.assertEqual(result["status"], INDETERMINATE)
        self.assertEqual(result["decision"], "DENY")

    def test_missing_payload(self):
        transport = FakeTransport(payload=None)
        result = validate_live_context(
            "synthetic-test-token",
            TEAM_ID,
            USER_ID,
            transport,
        )
        self.assertEqual(result["status"], INDETERMINATE)
        self.assertEqual(result["decision"], "DENY")

    def test_non_creator_is_not_authorized(self):
        payload = valid_payload()
        payload["user"]["isTeamCreator"] = False
        payload["team"]["teamCreator"] = "cccccccccccccccccccccccc"
        transport = FakeTransport(payload=payload)

        result = validate_live_context(
            "synthetic-test-token",
            TEAM_ID,
            USER_ID,
            transport,
        )
        self.assertEqual(result["status"], INDETERMINATE)
        self.assertEqual(result["decision"], "DENY")

    def test_transport_exception(self):
        def broken_transport(*args):
            raise OSError("synthetic failure")

        result = validate_live_context(
            "synthetic-test-token",
            TEAM_ID,
            USER_ID,
            broken_transport,
        )
        self.assertEqual(result["status"], INDETERMINATE)
        self.assertEqual(result["decision"], "DENY")

    def test_invalid_expected_id_blocks_network(self):
        transport = FakeTransport(payload=valid_payload())
        result = validate_live_context(
            "synthetic-test-token",
            "bad-id",
            USER_ID,
            transport,
        )
        self.assertEqual(result["status"], INVALID)
        self.assertEqual(transport.calls, 0)


class EvidenceLoggerTests(unittest.TestCase):

    def test_evidence_contains_no_personal_data_or_token(self):
        stages = {
            "transport": "TLS_HTTP_RESPONSE_OK",
            "authentication": "TOKEN_ACCEPTED_BY_API",
            "team_context": "VALID_CONTEXT",
            "identity_binding": "VALID_CREATOR_IDENTITY",
        }
        record = build_evidence(
            "VALIDATED_CREATOR_CONTEXT",
            stages,
            200,
        )
        serialized = json.dumps(record)

        self.assertNotIn(USER_ID, serialized)
        self.assertNotIn(TEAM_ID, serialized)
        self.assertNotIn("synthetic-test-token", serialized)
        self.assertFalse(record["credentials_logged"])
        self.assertFalse(record["personal_data_logged"])

    def test_evidence_rejects_arbitrary_data(self):
        with self.assertRaises(ValueError):
            build_evidence(
                "VALIDATED_CREATOR_CONTEXT",
                {"user_email": "person@example.com"},
            )

    def test_evidence_file_written(self):
        stages = {
            "transport": "TLS_HTTP_RESPONSE_OK",
            "authentication": "TOKEN_ACCEPTED_BY_API",
            "team_context": "VALID_CONTEXT",
            "identity_binding": "VALID_CREATOR_IDENTITY",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            result = append_evidence(
                str(path),
                "VALIDATED_CREATOR_CONTEXT",
                stages,
                200,
            )
            self.assertEqual(result["status"], "EVIDENCE_WRITTEN")
            self.assertTrue(path.exists())
            self.assertEqual(len(path.read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
