from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import policy
from .compliance import build_report
from .control import ControlPlane
from .integrity import PolicyIntegrityGuard, policy_fingerprint
from .license import LicenseClaims, LicenseError, LicenseMeter
from .models import ActionRequest, InputEnvelope, SharedChannelObservation
from .root_gate import Ed25519RootGate
from .tenancy import HaltSwitch, TenantPaths

MAX_TEXT_BYTES = 256 * 1024
MAX_FIELD_CHARS = 512
MAX_TAIL = 100


def _refusal(reason: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "code": 2, "reason": reason, "execute": False, **extra}


class NordefService:
    """Tool logic behind the MCP server. Identity, tenant and trust come from the operator,
    never from tool arguments, so a model cannot claim to be trusted or to be someone else."""

    def __init__(
        self,
        *,
        state_root: str | Path,
        tenant: str,
        agent_id: str,
        license_claims: LicenseClaims,
        mandate_keys: Mapping[str, Ed25519PublicKey],
        trusted_sources: Iterable[str] = (),
        policy_pin: str | None = None,
        max_ttl_seconds: int = 900,
    ):
        self.paths = TenantPaths.create(state_root, tenant)
        self.agent_id = agent_id
        self.license = license_claims
        self.trusted_sources = frozenset(trusted_sources)
        self.guard = PolicyIntegrityGuard(policy_pin)
        self.halt = HaltSwitch(self.paths)
        self.meter = LicenseMeter(self.paths.license_meter, license_claims)
        self.gate = Ed25519RootGate(mandate_keys, self.paths.replay, max_ttl_seconds=max_ttl_seconds)
        self.control = ControlPlane(
            self.paths.dir,
            root_gate=self.gate,
            context={"agent_id": agent_id, "tenant": tenant, "license_id": license_claims.license_id},
        )

    # ---- guards -------------------------------------------------------------

    def _admit(self, tool: str, envelope: InputEnvelope, request: ActionRequest,
               *, gated: bool) -> dict[str, Any] | None:
        if not self.guard.check():
            decision = self.control.record_event(
                envelope=envelope, request=request, code=2,
                state="blocked_integrity", reason="policy_integrity_failure",
            )
            return _refusal("policy_integrity_failure", state=decision.state)
        try:
            self.meter.admit(self.agent_id, tool)
        except LicenseError as exc:
            decision = self.control.record_event(
                envelope=envelope, request=request, code=2,
                state="blocked_license", reason=exc.reason,
            )
            return _refusal(exc.reason, state=decision.state)
        if gated and self.halt.halted():
            decision = self.control.record_event(
                envelope=envelope, request=request, code=2,
                state="halted_by_human", reason="human_stop_engaged",
            )
            return _refusal("human_stop_engaged", state=decision.state, halt=self.halt.status())
        return None

    def _read_admit(self, tool: str) -> dict[str, Any] | None:
        if not self.guard.check():
            return _refusal("policy_integrity_failure")
        try:
            self.meter.admit(self.agent_id, tool)
        except LicenseError as exc:
            return _refusal(exc.reason)
        return None

    def _envelope(self, source: str, text: str) -> InputEnvelope:
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ValueError("text_too_large")
        return InputEnvelope(source=source[:MAX_FIELD_CHARS], text=text,
                             trusted=source in self.trusted_sources)

    @staticmethod
    def _request(action: str, target: str, scope: str, side_effects: bool) -> ActionRequest:
        for value in (action, target, scope):
            if not isinstance(value, str) or len(value) > MAX_FIELD_CHARS:
                raise ValueError("invalid_request_field")
        return ActionRequest(action=action, target=target, scope=scope, side_effects=bool(side_effects))

    # ---- tools --------------------------------------------------------------

    def policy_list(self) -> dict[str, Any]:
        refused = self._read_admit("policy_list")
        if refused:
            return refused
        return {
            "ok": True,
            "decision_codes": {
                "0": "read-only / controlled: may proceed, nothing executed",
                "1": "side effect: held until a human-signed mandate",
                "2": "blocked",
            },
            "read_only_actions": sorted(policy._READ_ONLY_ACTIONS),
            "blocked_actions": sorted(policy._DANGEROUS_ACTIONS),
            "input_rule_count": len(policy._UNTRUSTED_INSTRUCTION_PATTERNS),
            "policy_fingerprint": policy_fingerprint(),
            "trusted_sources": sorted(self.trusted_sources),
            "max_mandate_ttl_seconds": self.gate.max_ttl_seconds,
            "halted": self.halt.halted(),
            "execute": False,
        }

    def policy_check(
        self, *, source: str, text: str, action: str, target: str, scope: str,
        side_effects: bool = False, channel_namespace: str | None = None,
        channel_writers: list[str] | None = None,
    ) -> dict[str, Any]:
        try:
            envelope = self._envelope(source, text)
            request = self._request(action, target, scope, side_effects)
        except ValueError as exc:
            return _refusal(str(exc))
        refused = self._admit("policy_check", envelope, request, gated=True)
        if refused:
            return refused
        channel = None
        if channel_namespace:
            channel = SharedChannelObservation(
                namespace=channel_namespace[:MAX_FIELD_CHARS],
                agent_id=self.agent_id,
                writable_by_agents=tuple(channel_writers or ()),
            )
        decision = self.control.evaluate(envelope, request, channel=channel)
        return {"ok": True, **decision.to_dict()}

    def mandate_verify(
        self, *, token: str, action: str, target: str, scope: str, side_effects: bool,
    ) -> dict[str, Any]:
        try:
            request = self._request(action, target, scope, side_effects)
        except ValueError as exc:
            return _refusal(str(exc))
        envelope = InputEnvelope(source="mandate_verify", text=token[:8192], trusted=False)
        refused = self._admit("mandate_verify", envelope, request, gated=True)
        if refused:
            return refused
        result = self.gate.verify(token, request, consume=False)
        return {
            "ok": True, "valid": result.valid, "reason": result.reason,
            "subject": result.subject, "key_id": result.key_id,
            "request_hash": request.request_hash(), "consumed": False, "execute": False,
        }

    def evidence_append(
        self, *, token: str, source: str, text: str, action: str, target: str,
        scope: str, side_effects: bool,
    ) -> dict[str, Any]:
        try:
            envelope = self._envelope(source, text)
            request = self._request(action, target, scope, side_effects)
        except ValueError as exc:
            return _refusal(str(exc))
        refused = self._admit("evidence_append", envelope, request, gated=True)
        if refused:
            return refused
        decision = self.control.evaluate(envelope, request, mandate_token=token)
        if decision.authorized:
            self.meter.count("authorized_actions")
        return {"ok": decision.authorized, **decision.to_dict()}

    def evidence_tail(self, count: int = 20) -> dict[str, Any]:
        refused = self._read_admit("evidence_tail")
        if refused:
            return refused
        verification = self.control.evidence.verify()
        count = max(0, min(int(count), MAX_TAIL))
        return {
            "ok": True,
            "chain_valid": verification.valid,
            "chain_reason": verification.reason,
            "records_total": verification.records,
            "records": self.control.evidence.tail(count) if verification.valid else [],
        }

    def compliance_status(self) -> dict[str, Any]:
        refused = self._read_admit("compliance_status")
        if refused:
            return refused
        report = build_report(
            self.control.evidence, tenant=self.paths.tenant,
            halt_status=self.halt.status(), license_info=self.license_info(),
        )
        return {"ok": True, **report}

    def license_info(self) -> dict[str, Any]:
        return {
            "license_id": self.license.license_id,
            "licensee": self.license.licensee,
            "expires_at": self.license.expires_at,
            "dev": self.license.dev,
            "usage": self.meter.usage(),
        }
