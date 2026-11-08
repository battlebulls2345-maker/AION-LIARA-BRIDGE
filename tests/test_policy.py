import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aion_adapter.policy import authorize, POLICY_VERSION

class PolicyTests(unittest.TestCase):

    def test_allowed_reads(self):
        paths = [
            "/vm",
            "/vm/vm123",
            "/vm/traffic-graph/vm123",
            "/vm/traffic-volume/vm123",
            "/vm/disk/vm123",
            "/vm/operation/vm123",
            "/plans",
            "/oss",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(authorize("GET", path), "READ")

    def test_modifying_methods_blocked(self):
        for method in ["POST", "PUT", "PATCH", "DELETE"]:
            with self.subTest(method=method):
                self.assertEqual(authorize(method, "/vm"), "BLOCK")

    def test_dangerous_routes_blocked(self):
        paths = [
            "/vm/unfreeze/vm123",
            "/vm/power/vm123",
            "/vm/reset-network/vm123",
            "/vm/reset-password/vm123",
            "/vm/resize/vm123",
            "/vm/disk/vm123/disk456",
            "/unknown",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(authorize("GET", path), "BLOCK")

    def test_path_injection_blocked(self):
        paths = [
            "/vm/../plans",
            "/vm?admin=true",
            "/vm%2F123",
            "//vm",
            "https://iaas-api.liara.ir/vm",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(authorize("GET", path), "BLOCK")

    def test_invalid_inputs_blocked(self):
        self.assertEqual(authorize("", "/vm"), "BLOCK")
        self.assertEqual(authorize("GET", ""), "BLOCK")
        self.assertEqual(authorize(None, "/vm"), "BLOCK")
        self.assertEqual(authorize("GET", None), "BLOCK")

    def test_policy_version(self):
        self.assertEqual(POLICY_VERSION, "AION_LIARA_READ_ONLY_V01")

if __name__ == "__main__":
    unittest.main(verbosity=2)
