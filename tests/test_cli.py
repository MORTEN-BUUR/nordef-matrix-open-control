from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class EvalCliTests(unittest.TestCase):
    def test_run_eval_cli_emits_machine_readable_pass(self):
        root = Path(__file__).parents[1]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(root / "src")
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    str(root / "scripts" / "run_eval.py"),
                    "--bank", str(root / "evals" / "openai_hf_incident_patterns.jsonl"),
                    "--state-dir", str(Path(tmp) / "state"),
                ],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["total"], 10)
        self.assertEqual(payload["failures"], 0)
        self.assertEqual(payload["executed"], 0)


if __name__ == "__main__":
    unittest.main()
