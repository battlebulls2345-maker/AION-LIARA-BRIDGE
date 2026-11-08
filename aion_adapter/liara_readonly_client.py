"""Fail-closed, read-only LIARA /v1/me client.

Transport and response parsing only.
This module does NOT establish identity or authorization.
"""

import json
import re
import ssl
import urllib.error
import urllib.request

POLICY_VERSION = "AION_LIARA_READONLY_CLIENT_V01"

BASE_URL = "https://api.liara.ir"
ENDPOINT = "/v1/me"
TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 1_048_576

TEAM_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{24}$")


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _default_transport(url, headers, timeout, max_bytes):
    """HTTPS transport with certificate verification and redirects disabled."""

    context = ssl.create_default_context()

    opener = urllib.request.build_opener(
        NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )

    request = urllib.request.Request(
        url=url,
        headers=headers,
        method="GET",
    )

    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.getcode()
            response_headers = response.headers
            body = response.read(max_bytes + 1)
            return status, response_headers, body

    except urllib.error.HTTPError as exc:
        # Do not read, print, or expose the error response body.
        return exc.code, exc.headers, b""


def fetch_current_user(token, team_id=None, transport=None):
    """Fetch /v1/me without exposing credentials or personal data in logs.

    Returns a result dictionary. A successful HTTP response is deliberately
    labelled TRANSPORT_OK_UNVALIDATED, not VALID.
    """

    if not isinstance(token, str) or not token:
        return {"status": "INVALID_INPUT", "payload": None}

    if token != token.strip() or "\r" in token or "\n" in token:
        return {"status": "INVALID_INPUT", "payload": None}

    if team_id is not None:
        if (
            not isinstance(team_id, str)
            or not TEAM_ID_PATTERN.fullmatch(team_id)
        ):
            return {"status": "INVALID_TEAM_ID", "payload": None}

    url = BASE_URL + ENDPOINT

    if team_id is not None:
        url += "?teamID=" + team_id

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }

    sender = transport or _default_transport

    try:
        status, response_headers, body = sender(
            url,
            headers,
            TIMEOUT_SECONDS,
            MAX_RESPONSE_BYTES,
        )
    except Exception:
        return {"status": "INDETERMINATE", "payload": None}

    if status in (401, 403):
        return {"status": "AUTH_REJECTED", "http_status": status,
                "payload": None}

    if status == 429:
        return {"status": "RATE_LIMITED", "http_status": status,
                "payload": None}

    if 300 <= status < 400:
        return {"status": "REDIRECT_BLOCKED", "http_status": status,
                "payload": None}

    if status != 200:
        return {"status": "HTTP_ERROR", "http_status": status,
                "payload": None}

    if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
        return {"status": "INDETERMINATE", "payload": None}

    try:
        content_type = response_headers.get("Content-Type", "")
    except Exception:
        return {"status": "INDETERMINATE", "payload": None}

    if content_type.split(";")[0].strip().lower() != "application/json":
        return {"status": "INDETERMINATE", "payload": None}

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"status": "INDETERMINATE", "payload": None}

    if not isinstance(payload, dict):
        return {"status": "INDETERMINATE", "payload": None}

    user = payload.get("user")
    if not isinstance(user, dict):
        return {"status": "INDETERMINATE", "payload": None}

    if team_id is not None:
        team = payload.get("team")
        if not isinstance(team, dict):
            return {"status": "INDETERMINATE", "payload": None}

        if team.get("_id") != team_id:
            return {"status": "INDETERMINATE", "payload": None}

    return {
        "status": "TRANSPORT_OK_UNVALIDATED",
        "http_status": 200,
        "payload": payload,
    }
