from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from nordef_open_control import EvidenceChain


class EvidenceChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "evidence.jsonl"

    def test_append_and_verify_chain(self):
        chain = EvidenceChain(self.path)
        first = chain.append(
            event_id="evt-1",
            source="web",
            category="prompt_injection",
            code=2,
            decision="blocked",
            input_bytes=b"untrusted raw prompt",
            action_taken=False,
            metadata={"rule_ids": ["PI-001"]},
        )
        second = chain.append(
            event_id="evt-2",
            source="human",
            category="read_only",
            code=0,
            decision="allowed",
            input_bytes=b"safe request",
            action_taken=False,
            metadata={},
        )
        self.assertEqual(second["previous_hash"], first["record_hash"])
        result = chain.verify()
        self.assertTrue(result.valid)
        self.assertEqual(result.records, 2)

    def test_raw_input_and_secret_values_are_not_serialized(self):
        chain = EvidenceChain(self.path)
        secret = "super-secret-value"
        chain.append(
            event_id="evt-1",
            source="web",
            category="blocked",
            code=2,
            decision="blocked",
            input_bytes=secret.encode(),
            action_taken=False,
            metadata={"api_key": secret, "safe_label": "blocked"},
        )
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn(secret, text)
        self.assertNotIn("api_key", text)
        record = json.loads(text)
        self.assertEqual(record["input_sha256"], __import__("hashlib").sha256(secret.encode()).hexdigest())
        self.assertEqual(record["metadata"], {"safe_label": "blocked"})

    def test_tampering_is_detected(self):
        chain = EvidenceChain(self.path)
        chain.append(
            event_id="evt-1", source="web", category="blocked", code=2,
            decision="blocked", input_bytes=b"x", action_taken=False, metadata={},
        )
        record = json.loads(self.path.read_text(encoding="utf-8"))
        record["decision"] = "allowed"
        self.path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        result = chain.verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "record_hash_mismatch")

    def test_corrupt_json_fails_closed(self):
        self.path.write_text("{broken\n", encoding="utf-8")
        result = EvidenceChain(self.path).verify()
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "invalid_json")


if __name__ == "__main__":
    unittest.main()
