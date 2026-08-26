from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from nordef_open_control.eval import run_eval_bank


class EvalBankTests(unittest.TestCase):
    def test_incident_pattern_bank_matches_all_expected_codes_and_never_executes(self):
        bank = Path(__file__).parents[1] / "evals" / "openai_hf_incident_patterns.jsonl"
        with tempfile.TemporaryDirectory() as tmp:
            result = run_eval_bank(bank, Path(tmp))
        self.assertEqual(result["total"], 10)
        self.assertEqual(result["failures"], 0)
        self.assertEqual(result["executed"], 0)
        self.assertEqual(result["counts"], {"0": 3, "1": 2, "2": 5})
        self.assertTrue(all(row["passed"] for row in result["rows"]))

    def test_duplicate_ids_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            bank = Path(tmp) / "bad.jsonl"
            line = '{"id":"same","input":{"source":"human","text":"read","trusted":true},"action":{"action":"read","target":"x","scope":"read","side_effects":false},"expected_code":0}'
            bank.write_text(line + "\n" + line + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate eval id"):
                run_eval_bank(bank, Path(tmp) / "state")


if __name__ == "__main__":
    unittest.main()
