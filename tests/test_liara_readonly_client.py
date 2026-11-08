import sys
import json
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aion_adapter.liara_readonly_client import (
    fetch_current_user,
    BASE_URL,
    ENDPOINT,
    POLICY_VERSION,
)

TOKEN = "synthetic-test-token"
TEAM_ID = "0123456789abcdef01234567"


class FakeTransport:
    def __init__(self, status=200, payload=None,
                 content_type="application/json", body=None):
        self.status = status
        self.payload = payload if payload is not None else {
            "user": {"_id": "synthetic-user"}
        }
        self.content_type = content_type
        self.body = body
        self.calls = []

    def __call__(self, url, headers, timeout, max_bytes):
        self.calls.append((url, headers, timeout, max_bytes))

        body = self.body
        if body is None:
            body = json.dumps(self.payload).encode("utf-8")

        return (
            self.status,
            {"Content-Type": self.content_type},
            body,
        )


class ReadOnlyClientTests(unittest.TestCase):

    def test_policy_version(self):
        self.assertEqual(
            POLICY_VERSION,
            "AION_LIARA_READONLY_CLIENT_V01",
        )

    def test_personal_profile_request(self):
        transport = FakeTransport()

        result = fetch_current_user(TOKEN, transport=transport)

        self.assertEqual(result["status"], "TRANSPORT_OK_UNVALIDATED")
        self.assertEqual(len(transport.calls), 1)

        url, headers, timeout, max_bytes = transport.calls[0]

        self.assertEqual(url, BASE_URL + ENDPOINT)
        self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(timeout, 10)
        self.assertEqual(max_bytes, 1_048_576)

    def test_team_context_request(self):
        transport = FakeTransport(
            payload={
                "user": {"_id": "synthetic-user"},
                "team": {"_id": TEAM_ID},
            }
        )

        result = fetch_current_user(
            TOKEN,
            team_id=TEAM_ID,
            transport=transport,
        )

        self.assertEqual(result["status"], "TRANSPORT_OK_UNVALIDATED")
        self.assertTrue(transport.calls[0][0].endswith("?teamID=" + TEAM_ID))

    def test_invalid_team_id_blocked_before_transport(self):
        transport = FakeTransport()

        result = fetch_current_user(
            TOKEN,
            team_id="../invalid",
            transport=transport,
        )

        self.assertEqual(result["status"], "INVALID_TEAM_ID")
        self.assertEqual(len(transport.calls), 0)

    def test_empty_token_blocked(self):
        transport = FakeTransport()

        result = fetch_current_user("", transport=transport)

        self.assertEqual(result["status"], "INVALID_INPUT")
        self.assertEqual(len(transport.calls), 0)

    def test_token_with_newline_blocked(self):
        transport = FakeTransport()

        result = fetch_current_user(
            "synthetic-token\ninjected",
            transport=transport,
        )

        self.assertEqual(result["status"], "INVALID_INPUT")
        self.assertEqual(len(transport.calls), 0)

    def test_unauthorized_response(self):
        result = fetch_current_user(
            TOKEN,
            transport=FakeTransport(status=401),
        )

        self.assertEqual(result["status"], "AUTH_REJECTED")

    def test_forbidden_response(self):
        result = fetch_current_user(
            TOKEN,
            transport=FakeTransport(status=403),
        )

        self.assertEqual(result["status"], "AUTH_REJECTED")

    def test_rate_limit_no_retry(self):
        transport = FakeTransport(status=429)

        result = fetch_current_user(TOKEN, transport=transport)

        self.assertEqual(result["status"], "RATE_LIMITED")
        self.assertEqual(len(transport.calls), 1)

    def test_redirect_blocked(self):
        result = fetch_current_user(
            TOKEN,
            transport=FakeTransport(status=302),
        )

        self.assertEqual(result["status"], "REDIRECT_BLOCKED")

    def test_server_error(self):
        result = fetch_current_user(
            TOKEN,
            transport=FakeTransport(status=500),
        )

        self.assertEqual(result["status"], "HTTP_ERROR")

    def test_non_json_response(self):
        result = fetch_current_user(
            TOKEN,
            transport=FakeTransport(content_type="text/html"),
        )

        self.assertEqual(result["status"], "INDETERMINATE")

    def test_malformed_json(self):
        result = fetch_current_user(
            TOKEN,
            transport=FakeTransport(body=b"{broken"),
        )

        self.assertEqual(result["status"], "INDETERMINATE")

    def test_missing_user_object(self):
        result = fetch_current_user(
            TOKEN,
            transport=FakeTransport(payload={"data": {}}),
        )

        self.assertEqual(result["status"], "INDETERMINATE")

    def test_missing_team_object(self):
        result = fetch_current_user(
            TOKEN,
            team_id=TEAM_ID,
            transport=FakeTransport(
                payload={"user": {"_id": "synthetic-user"}}
            ),
        )

        self.assertEqual(result["status"], "INDETERMINATE")

    def test_wrong_team_id(self):
        result = fetch_current_user(
            TOKEN,
            team_id=TEAM_ID,
            transport=FakeTransport(
                payload={
                    "user": {"_id": "synthetic-user"},
                    "team": {"_id": "ffffffffffffffffffffffff"},
                }
            ),
        )

        self.assertEqual(result["status"], "INDETERMINATE")

    def test_oversized_response(self):
        result = fetch_current_user(
            TOKEN,
            transport=FakeTransport(
                body=b"x" * (1_048_577)
            ),
        )

        self.assertEqual(result["status"], "INDETERMINATE")

    def test_transport_exception(self):
        def failing_transport(*args):
            raise TimeoutError("synthetic timeout")

        result = fetch_current_user(
            TOKEN,
            transport=failing_transport,
        )

        self.assertEqual(result["status"], "INDETERMINATE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
