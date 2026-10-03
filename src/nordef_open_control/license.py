from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .locking import exclusive_lock

LICENSE_PREFIX = "NORDEF1"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class LicenseError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class LicenseClaims:
    license_id: str
    licensee: str
    key_id: str
    scopes: tuple[str, ...]
    max_agents: int
    max_requests: int  # per calendar month (UTC); 0 = unlimited
    issued_at: str
    expires_at: str
    test_only: bool = False
    dev: bool = False

    def to_dict(self) -> dict:
        value = asdict(self)
        value["scopes"] = list(self.scopes)
        return value

    def allows(self, tool: str) -> bool:
        return "*" in self.scopes or tool in self.scopes


def sign_license(private_key: Ed25519PrivateKey, claims: LicenseClaims) -> str:
    payload = _b64e(json.dumps(claims.to_dict(), sort_keys=True, separators=(",", ":")).encode())
    signed = f"{LICENSE_PREFIX}.{payload}".encode("ascii")
    return f"{LICENSE_PREFIX}.{payload}.{_b64e(private_key.sign(signed))}"


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def verify_license(
    token: str,
    vendor_keys: Mapping[str, Ed25519PublicKey],
    *,
    allow_dev: bool = False,
    now: datetime | None = None,
) -> LicenseClaims:
    try:
        prefix, payload, signature = token.strip().split(".")
        if prefix != LICENSE_PREFIX:
            raise ValueError("prefix")
        data = json.loads(_b64d(payload))
        data["scopes"] = tuple(data.get("scopes") or ())
        claims = LicenseClaims(**data)
        sig = _b64d(signature)
    except Exception as exc:
        raise LicenseError("malformed_license") from exc
    if claims.test_only:
        raise LicenseError("test_only_license")
    if claims.dev and not allow_dev:
        raise LicenseError("dev_license_not_allowed")
    key = vendor_keys.get(claims.key_id)
    if key is None:
        raise LicenseError("unknown_license_key")
    try:
        key.verify(sig, f"{prefix}.{payload}".encode("ascii"))
    except (InvalidSignature, ValueError) as exc:
        raise LicenseError("invalid_license_signature") from exc
    try:
        issued = _parse_time(claims.issued_at)
        expires = _parse_time(claims.expires_at)
    except Exception as exc:
        raise LicenseError("invalid_license_time") from exc
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if issued > current or expires <= current:
        raise LicenseError("license_not_valid_now")
    if claims.max_agents < 1 or claims.max_requests < 0 or not claims.scopes:
        raise LicenseError("invalid_license_limits")
    return claims


@dataclass
class LicenseMeter:
    """Per-license monthly request counter and agent roster, shared across processes."""

    path: Path
    claims: LicenseClaims
    _period: str = field(default="", init=False)

    def admit(self, agent_id: str, tool: str, *, now: datetime | None = None) -> None:
        if not self.claims.allows(tool):
            raise LicenseError("tool_not_in_license_scope")
        period = (now or datetime.now(timezone.utc)).strftime("%Y-%m")
        with exclusive_lock(self.path):
            state = self._load()
            usage = state.setdefault(self.claims.license_id, {})
            month = usage.setdefault(period, {"requests": 0, "agents": []})
            if agent_id not in month["agents"]:
                if len(month["agents"]) >= self.claims.max_agents:
                    raise LicenseError("max_agents_exceeded")
                month["agents"].append(agent_id)
            if self.claims.max_requests and month["requests"] >= self.claims.max_requests:
                raise LicenseError("max_requests_exceeded")
            month["requests"] += 1
            self._store(state)

    def count(self, metric: str, *, now: datetime | None = None) -> None:
        """Increment a billing metric (e.g. human-authorized side effects) for this month."""
        period = (now or datetime.now(timezone.utc)).strftime("%Y-%m")
        with exclusive_lock(self.path):
            state = self._load()
            month = state.setdefault(self.claims.license_id, {}).setdefault(
                period, {"requests": 0, "agents": []}
            )
            month[metric] = int(month.get(metric, 0)) + 1
            self._store(state)

    def usage(self) -> dict:
        with exclusive_lock(self.path):
            return self._load().get(self.claims.license_id, {})

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise LicenseError("license_meter_unavailable") from exc
        if not isinstance(value, dict):
            raise LicenseError("license_meter_unavailable")
        return value

    def _store(self, state: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
