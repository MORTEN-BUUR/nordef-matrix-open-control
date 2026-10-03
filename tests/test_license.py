from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nordef_open_control.license import LicenseError, verify_license

from helpers import make_license, make_service


class LicenseTests(unittest.TestCase):
    def setUp(self):
        self.vendor = Ed25519PrivateKey.generate()
        self.keys = {"vendor-1": self.vendor.public_key()}

    def reject(self, token, reason, **kwargs):
        with self.assertRaises(LicenseError) as ctx:
            verify_license(token, self.keys, **kwargs)
        self.assertEqual(ctx.exception.reason, reason)

    def test_valid_license(self):
        claims = verify_license(make_license(self.vendor), self.keys)
        self.assertEqual(claims.licensee, "Test AS")
        self.assertTrue(make_license(self.vendor).startswith("NORDEF1."))

    def test_rejections(self):
        now = datetime.now(timezone.utc)
        self.reject("garbage", "malformed_license")
        self.reject(make_license(self.vendor, test_only=True), "test_only_license")
        self.reject(make_license(self.vendor, dev=True), "dev_license_not_allowed")
        self.reject(make_license(self.vendor, key_id="other"), "unknown_license_key")
        self.reject(make_license(Ed25519PrivateKey.generate()), "invalid_license_signature")
        self.reject(make_license(self.vendor, expires_at=(now - timedelta(seconds=1)).isoformat()),
                    "license_not_valid_now")
        self.reject(make_license(self.vendor, max_agents=0), "invalid_license_limits")

    def test_tampered_payload_rejected(self):
        prefix, payload, sig = make_license(self.vendor).split(".")
        other = make_license(self.vendor, max_agents=999).split(".")[1]
        self.reject(f"{prefix}.{other}.{sig}", "invalid_license_signature")

    def test_scope_and_limits_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            scoped = make_service(tmp, tenant="scoped", license_overrides={
                "license_id": "lic-scoped", "scopes": ("policy_check",)})
            self.assertEqual(scoped.policy_list()["reason"], "tool_not_in_license_scope")

            limited = make_service(tmp, tenant="limited", license_overrides={
                "license_id": "lic-limited", "max_requests": 2})
            for _ in range(2):
                self.assertTrue(limited.policy_list()["ok"])
            self.assertEqual(limited.policy_list()["reason"], "max_requests_exceeded")

            vendor = Ed25519PrivateKey.generate()
            overrides = {"license_id": "lic-agents", "max_agents": 1}
            first = make_service(tmp, tenant="agents", agent_id="a1", vendor_key=vendor,
                                 license_overrides=overrides)
            second = make_service(tmp, tenant="agents", agent_id="a2", vendor_key=vendor,
                                  license_overrides=overrides)
            self.assertTrue(first.policy_list()["ok"])
            self.assertEqual(second.policy_list()["reason"], "max_agents_exceeded")


if __name__ == "__main__":
    unittest.main()
