from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nordef_open_control import ActionRequest, Ed25519RootGate, MandateClaims
from nordef_open_control.root_gate import sign_mandate


class RootGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.gate = Ed25519RootGate(
            public_keys={"root-1": self.public},
            replay_path=Path(self.tmp.name) / "replay.json",
            max_ttl_seconds=900,
        )
        self.action = ActionRequest(
            action="update_config",
            target="lab-service",
            scope="write:config",
            side_effects=True,
        )

    def claims(self, **overrides):
        now = datetime.now(timezone.utc)
        values = dict(
            subject="human-root",
            action=self.action.action,
            target=self.action.target,
            scope=self.action.scope,
            side_effects=True,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=5)).isoformat(),
            nonce="nonce-1234567890",
            request_hash=self.action.request_hash(),
            key_id="root-1",
            test_only=False,
        )
        values.update(overrides)
        return MandateClaims(**values)

    def test_valid_signature_authorizes_exact_dry_run_request(self):
        token = sign_mandate(self.private, self.claims())
        result = self.gate.verify(token, self.action, consume=True)
        self.assertTrue(result.valid)
        self.assertEqual(result.subject, "human-root")

    def test_action_mismatch_fails_closed(self):
        token = sign_mandate(self.private, self.claims(action="delete"))
        result = self.gate.verify(token, self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "action_mismatch")

    def test_target_mismatch_fails_closed(self):
        token = sign_mandate(self.private, self.claims(target="other-service"))
        result = self.gate.verify(token, self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "target_mismatch")

    def test_scope_mismatch_fails_closed(self):
        token = sign_mandate(self.private, self.claims(scope="write:anything"))
        result = self.gate.verify(token, self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "scope_mismatch")

    def test_request_hash_mismatch_fails_closed(self):
        token = sign_mandate(self.private, self.claims(request_hash="0" * 64))
        result = self.gate.verify(token, self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "request_hash_mismatch")

    def test_expired_mandate_fails_closed(self):
        now = datetime.now(timezone.utc)
        token = sign_mandate(self.private, self.claims(
            issued_at=(now - timedelta(minutes=10)).isoformat(),
            expires_at=(now - timedelta(minutes=1)).isoformat(),
        ))
        result = self.gate.verify(token, self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "expired")

    def test_excessive_ttl_fails_closed(self):
        now = datetime.now(timezone.utc)
        token = sign_mandate(self.private, self.claims(
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=901)).isoformat(),
        ))
        result = self.gate.verify(token, self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ttl_exceeds_limit")

    def test_future_issue_time_fails_closed(self):
        now = datetime.now(timezone.utc)
        token = sign_mandate(self.private, self.claims(
            issued_at=(now + timedelta(minutes=2)).isoformat(),
            expires_at=(now + timedelta(minutes=4)).isoformat(),
        ))
        result = self.gate.verify(token, self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "issued_in_future")

    def test_test_only_signature_cannot_authorize(self):
        token = sign_mandate(self.private, self.claims(test_only=True))
        result = self.gate.verify(token, self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "test_only_attestation")

    def test_replay_is_rejected_across_gate_instances(self):
        token = sign_mandate(self.private, self.claims())
        self.assertTrue(self.gate.verify(token, self.action, consume=True).valid)
        gate2 = Ed25519RootGate(
            public_keys={"root-1": self.public},
            replay_path=Path(self.tmp.name) / "replay.json",
        )
        result = gate2.verify(token, self.action, consume=True)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "replay")

    def test_malformed_replay_registry_fails_closed(self):
        replay = Path(self.tmp.name) / "replay.json"
        replay.write_text("not-json", encoding="utf-8")
        token = sign_mandate(self.private, self.claims())
        result = self.gate.verify(token, self.action, consume=True)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "replay_registry_unavailable")

    def test_unknown_key_and_bad_signature_fail_closed(self):
        other = Ed25519PrivateKey.generate()
        unknown = sign_mandate(other, self.claims(key_id="unknown"))
        self.assertEqual(self.gate.verify(unknown, self.action).reason, "unknown_key")
        token = json.loads(sign_mandate(self.private, self.claims()))
        token["signature"] = "AAAA"
        result = self.gate.verify(json.dumps(token), self.action)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "invalid_signature")


if __name__ == "__main__":
    unittest.main()
