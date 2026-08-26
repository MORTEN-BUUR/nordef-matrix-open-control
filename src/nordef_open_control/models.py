from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class InputEnvelope:
    source: str
    text: str
    trusted: bool = False


@dataclass(frozen=True)
class ActionRequest:
    action: str
    target: str
    scope: str
    side_effects: bool = False

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "scope": self.scope,
            "side_effects": self.side_effects,
            "target": self.target,
        }

    def request_hash(self) -> str:
        raw = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SharedChannelObservation:
    namespace: str
    agent_id: str
    writable_by_agents: tuple[str, ...]
    externally_reachable: bool = False


@dataclass(frozen=True)
class MandateClaims:
    subject: str
    action: str
    target: str
    scope: str
    side_effects: bool
    issued_at: str
    expires_at: str
    nonce: str
    request_hash: str
    key_id: str
    test_only: bool = False

    def canonical_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "MandateClaims":
        return cls(**value)


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str
    subject: str | None = None
    key_id: str | None = None


@dataclass(frozen=True)
class Decision:
    code: int
    state: str
    reason: str
    authorized: bool = False
    execute: bool = False
    input_sha256: str | None = None
    request_hash: str | None = None
    action_manifest: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
