from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Callable

from .channels import classify_channel
from .evidence import EvidenceChain
from .models import ActionRequest, Decision, InputEnvelope, SharedChannelObservation
from .policy import CODE_BLOCK, CODE_REVIEW, classify_action, classify_input
from .root_gate import Ed25519RootGate


class ControlPlane:
    """Model-independent policy gate. This LAB candidate never executes actions."""

    def __init__(
        self,
        state_dir: str | Path,
        root_gate: Ed25519RootGate | None = None,
        context: dict | None = None,
    ):
        self.state_dir = Path(state_dir)
        self.root_gate = root_gate
        self.evidence = EvidenceChain(self.state_dir / "evidence.jsonl")
        # Operator-set identity (agent_id, tenant, license_id) stamped on every record.
        self.context = dict(context or {})

    def record_event(
        self,
        *,
        envelope: InputEnvelope,
        request: ActionRequest,
        code: int,
        state: str,
        reason: str,
        extra_metadata: dict | None = None,
    ) -> Decision:
        """Record a decision made outside ``evaluate`` (halt, license refusal, integrity failure)."""
        return self._decision(
            envelope=envelope, request=request, code=code, state=state, reason=reason,
            extra_metadata=extra_metadata,
        )

    def _decision(
        self,
        *,
        envelope: InputEnvelope,
        request: ActionRequest,
        code: int,
        state: str,
        reason: str,
        authorized: bool = False,
        action_manifest: dict | None = None,
        extra_metadata: dict | None = None,
    ) -> Decision:
        decision = Decision(
            code=code,
            state=state,
            reason=reason,
            authorized=authorized,
            execute=False,
            input_sha256=hashlib.sha256(envelope.text.encode("utf-8")).hexdigest(),
            request_hash=request.request_hash(),
            action_manifest=action_manifest,
        )
        self.evidence.append(
            event_id=str(uuid.uuid4()),
            source=envelope.source,
            category=reason,
            code=code,
            decision=state,
            input_bytes=envelope.text.encode("utf-8"),
            action_taken=False,
            metadata={
                **self.context,
                **(extra_metadata or {}),
                "reason_code": reason,
                "result_state": state,
                "request_hash": request.request_hash(),
            },
        )
        return decision

    def evaluate(
        self,
        envelope: InputEnvelope,
        request: ActionRequest,
        *,
        mandate_token: str | None = None,
        channel: SharedChannelObservation | None = None,
        model_transport: Callable[[str], object] | None = None,
    ) -> Decision:
        channel_code, channel_reason = classify_channel(channel)
        if channel_code == CODE_BLOCK:
            return self._decision(
                envelope=envelope, request=request, code=2,
                state="blocked_shared_channel", reason=channel_reason,
            )

        input_code, input_reason = classify_input(envelope)
        if input_code == CODE_BLOCK:
            return self._decision(
                envelope=envelope, request=request, code=2,
                state="blocked_before_model", reason=input_reason,
            )

        action_code, action_reason = classify_action(request)
        if action_code == CODE_BLOCK:
            return self._decision(
                envelope=envelope, request=request, code=2,
                state="blocked_policy", reason=action_reason,
            )
        if action_code == CODE_REVIEW:
            if mandate_token and self.root_gate:
                verification = self.root_gate.verify(mandate_token, request, consume=True)
                mandate_metadata = {
                    "mandate_sha256": hashlib.sha256(mandate_token.encode("utf-8")).hexdigest(),
                    "key_id": verification.key_id,
                    "subject": verification.subject,
                }
                if verification.valid:
                    manifest = {
                        **request.canonical_dict(),
                        "request_hash": request.request_hash(),
                        "execute": False,
                    }
                    return self._decision(
                        envelope=envelope, request=request, code=1,
                        state="authorized_dry_run", reason="root_verified_dry_run_only",
                        authorized=True, action_manifest=manifest,
                        extra_metadata=mandate_metadata,
                    )
                return self._decision(
                    envelope=envelope, request=request, code=2,
                    state="blocked_invalid_mandate", reason=verification.reason,
                    extra_metadata=mandate_metadata,
                )
            return self._decision(
                envelope=envelope, request=request, code=1,
                state="held_for_root", reason=action_reason,
            )

        if model_transport is not None:
            model_transport(envelope.text)
        return self._decision(
            envelope=envelope, request=request, code=0,
            state="allowed_read_only", reason=input_reason,
        )
