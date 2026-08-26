from __future__ import annotations

import re

from .models import ActionRequest, InputEnvelope

CODE_SAFE = 0
CODE_REVIEW = 1
CODE_BLOCK = 2

_UNTRUSTED_INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore (?:all |the )?(?:previous|prior) instructions?\b", re.I),
    re.compile(r"\b(?:reveal|send|upload|exfiltrate)\b.{0,80}\b(?:secret|credential|token|password|key)s?\b", re.I),
    re.compile(r"\broot (?:verified|approved|override)\b", re.I),
    re.compile(r"\bdisable (?:the )?(?:guard|safety|policy|logging|audit)s?\b", re.I),
    re.compile(r"\b(?:system|developer) message\s*:", re.I),
)

_DANGEROUS_ACTIONS = {
    "delete", "delete_production", "exfiltrate", "credential_send",
    "disable_audit", "change_firewall", "open_wan", "arbitrary_shell",
    "publish_private_data", "model_weight_export",
}

_READ_ONLY_ACTIONS = {
    "read", "summarize", "classify", "inspect", "verify", "search",
    "draft", "hash", "list", "health_check",
}


def classify_input(envelope: InputEnvelope) -> tuple[int, str]:
    if not isinstance(envelope.text, str) or not envelope.text.strip():
        return CODE_REVIEW, "empty_or_invalid_input"
    if not envelope.trusted:
        for pattern in _UNTRUSTED_INSTRUCTION_PATTERNS:
            if pattern.search(envelope.text):
                return CODE_BLOCK, "untrusted_instruction_attempt"
    return CODE_SAFE, "input_data_boundary_ok"


def classify_action(request: ActionRequest) -> tuple[int, str]:
    action = request.action.strip().lower()
    if action in _DANGEROUS_ACTIONS:
        return CODE_BLOCK, "dangerous_action"
    if request.side_effects:
        return CODE_REVIEW, "side_effect_requires_root"
    if action in _READ_ONLY_ACTIONS or request.scope.strip().lower() == "read":
        return CODE_SAFE, "read_only"
    return CODE_REVIEW, "unknown_action_requires_review"
