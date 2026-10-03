from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from nordef_open_control import ActionRequest
from nordef_open_control.cli import admin_main, load_private_key, load_public_keys, root_main
from nordef_open_control.root_gate import Ed25519RootGate


def run(main, argv) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    return code, out.getvalue()


class OperatorCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_keygen_and_signed_mandate_verify(self):
        key_path = self.dir / "root.pem"
        code, _ = run(root_main, ["keygen", "--key-id", "root-1", "--out", str(key_path)])
        self.assertEqual(code, 0)
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        load_private_key(key_path)
        keys = load_public_keys(key_path.with_suffix(".pub.json"))
        code, token = run(root_main, [
            "sign-mandate", "--key", str(key_path), "--key-id", "root-1", "--subject", "cfo",
            "--action", "pay", "--target", "inv-9", "--scope", "write:payments", "--side-effects",
        ])
        gate = Ed25519RootGate(keys, self.dir / "replay.json")
        result = gate.verify(token.strip(), ActionRequest("pay", "inv-9", "write:payments", True))
        self.assertTrue(result.valid, result.reason)
        self.assertEqual(result.subject, "cfo")

    def test_halt_resume_and_report(self):
        state = str(self.dir / "state")
        run(admin_main, ["--state-dir", state, "status", "--tenant", "acme"])
        code, out = run(admin_main, ["--state-dir", state, "halt", "--operator", "cto",
                                     "--reason", "drill"])
        self.assertEqual(code, 0)
        self.assertIn("HALT", out)
        _, status = run(admin_main, ["--state-dir", state, "status", "--tenant", "acme"])
        self.assertEqual(json.loads(status)["halt"]["scope"], "global")
        run(admin_main, ["--state-dir", state, "resume", "--operator", "cto"])
        code, report = run(admin_main, ["--state-dir", state, "report", "--tenant", "acme",
                                        "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(report)
        self.assertEqual(len(data["human_oversight"]["halt_history"]), 2)
        self.assertFalse(data["human_oversight"]["halt_active"])
        code, _ = run(admin_main, ["--state-dir", state, "verify"])
        self.assertEqual(code, 0)
        code, md = run(admin_main, ["--state-dir", state, "report", "--tenant", "acme"])
        self.assertIn("26(6)", md)


if __name__ == "__main__":
    unittest.main()
