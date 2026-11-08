import re

POLICY_VERSION = "AION_LIARA_READ_ONLY_V01"

# Kizárólag dokumentált, olvasási célú útvonalak.
ALLOWED_GET = [
    re.compile(r"^/vm$"),
    re.compile(r"^/vm/[A-Za-z0-9_-]+$"),
    re.compile(r"^/vm/traffic-graph/[A-Za-z0-9_-]+$"),
    re.compile(r"^/vm/traffic-volume/[A-Za-z0-9_-]+$"),
    re.compile(r"^/vm/disk/[A-Za-z0-9_-]+$"),
    re.compile(r"^/vm/operation/[A-Za-z0-9_-]+$"),
    re.compile(r"^/plans$"),
    re.compile(r"^/oss$"),
]

def authorize(method: str, path: str) -> str:
    if not isinstance(method, str) or not isinstance(path, str):
        return "BLOCK"

    method = method.upper()

    # Nincs query, fragment, kódolt útvonal vagy abszolút URL.
    if (
        not path.startswith("/")
        or "?" in path
        or "#" in path
        or "%" in path
        or "\\" in path
        or "//" in path
        or ".." in path
    ):
        return "BLOCK"

    if method != "GET":
        return "BLOCK"

    if any(pattern.fullmatch(path) for pattern in ALLOWED_GET):
        return "READ"

    return "BLOCK"
