from __future__ import annotations

import hashlib
import json

from . import policy


def policy_fingerprint() -> str:
    """SHA-256 over the live policy tables (input patterns, blocked and read-only actions)."""
    material = {
        "input_patterns": [
            [p.pattern, int(p.flags)] for p in policy._UNTRUSTED_INSTRUCTION_PATTERNS
        ],
        "dangerous_actions": sorted(policy._DANGEROUS_ACTIONS),
        "read_only_actions": sorted(policy._READ_ONLY_ACTIONS),
        "codes": [policy.CODE_SAFE, policy.CODE_REVIEW, policy.CODE_BLOCK],
    }
    raw = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class PolicyIntegrityGuard:
    """Fail closed if the policy tables differ from the pinned or startup fingerprint.

    Pin ``expected`` to a release value to also catch on-disk modification before startup;
    otherwise the fingerprint taken at startup is used and runtime tampering is detected.
    """

    def __init__(self, expected: str | None = None):
        self.expected = expected or policy_fingerprint()

    def check(self) -> bool:
        try:
            return policy_fingerprint() == self.expected
        except Exception:
            return False
