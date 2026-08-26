from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import ActionRequest, MandateClaims, VerificationResult
from .replay import FileReplayRegistry, ReplayRegistryError


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def sign_mandate(private_key: Ed25519PrivateKey, claims: MandateClaims) -> str:
    signature = private_key.sign(claims.canonical_bytes())
    return json.dumps({
        "claims": claims.canonical_dict(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }, sort_keys=True, separators=(",", ":"))


class Ed25519RootGate:
    """Verify short-lived, exact-scope human mandates outside model text."""

    def __init__(
        self,
        public_keys: Mapping[str, Ed25519PublicKey],
        replay_path: str | Path,
        max_ttl_seconds: int = 900,
        max_clock_skew_seconds: int = 30,
    ):
        self.public_keys = dict(public_keys)
        self.replay = FileReplayRegistry(replay_path)
        self.max_ttl_seconds = max_ttl_seconds
        self.max_clock_skew = timedelta(seconds=max_clock_skew_seconds)

    def verify(
        self,
        token: str,
        request: ActionRequest,
        *,
        consume: bool = False,
        now: datetime | None = None,
    ) -> VerificationResult:
        try:
            envelope = json.loads(token)
            claims = MandateClaims.from_dict(envelope["claims"])
            signature = base64.b64decode(envelope["signature"], validate=True)
        except Exception:
            return VerificationResult(False, "malformed_token")

        if claims.test_only:
            return VerificationResult(False, "test_only_attestation", key_id=claims.key_id)
        key = self.public_keys.get(claims.key_id)
        if key is None:
            return VerificationResult(False, "unknown_key", key_id=claims.key_id)
        try:
            key.verify(signature, claims.canonical_bytes())
        except (InvalidSignature, ValueError):
            return VerificationResult(False, "invalid_signature", key_id=claims.key_id)

        try:
            issued = _parse_time(claims.issued_at)
            expires = _parse_time(claims.expires_at)
        except Exception:
            return VerificationResult(False, "invalid_time", key_id=claims.key_id)
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        ttl = (expires - issued).total_seconds()
        if issued > current + self.max_clock_skew:
            return VerificationResult(False, "issued_in_future", key_id=claims.key_id)
        if expires <= current:
            return VerificationResult(False, "expired", key_id=claims.key_id)
        if ttl <= 0 or ttl > self.max_ttl_seconds:
            return VerificationResult(False, "ttl_exceeds_limit", key_id=claims.key_id)
        if claims.action != request.action:
            return VerificationResult(False, "action_mismatch", key_id=claims.key_id)
        if claims.target != request.target:
            return VerificationResult(False, "target_mismatch", key_id=claims.key_id)
        if claims.scope != request.scope:
            return VerificationResult(False, "scope_mismatch", key_id=claims.key_id)
        if claims.side_effects != request.side_effects:
            return VerificationResult(False, "side_effect_mismatch", key_id=claims.key_id)
        if claims.request_hash != request.request_hash():
            return VerificationResult(False, "request_hash_mismatch", key_id=claims.key_id)
        if not claims.subject or len(claims.nonce) < 12:
            return VerificationResult(False, "invalid_claims", key_id=claims.key_id)

        try:
            if self.replay.is_used(claims.nonce):
                return VerificationResult(False, "replay", key_id=claims.key_id)
            if consume and not self.replay.consume(claims.nonce):
                return VerificationResult(False, "replay", key_id=claims.key_id)
        except ReplayRegistryError:
            return VerificationResult(False, "replay_registry_unavailable", key_id=claims.key_id)
        return VerificationResult(True, "verified", subject=claims.subject, key_id=claims.key_id)
