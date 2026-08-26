"""NORDEF Matrix Open Control — model-independent AI safety belt."""

from .control import ControlPlane
from .evidence import ChainVerification, EvidenceChain
from .models import (
    ActionRequest,
    Decision,
    InputEnvelope,
    MandateClaims,
    SharedChannelObservation,
    VerificationResult,
)
from .policy import CODE_BLOCK, CODE_REVIEW, CODE_SAFE, classify_action, classify_input
from .root_gate import Ed25519RootGate

__version__ = "3.0.0-lab"

__all__ = [
    "ActionRequest",
    "ChainVerification",
    "CODE_BLOCK",
    "CODE_REVIEW",
    "CODE_SAFE",
    "ControlPlane",
    "Decision",
    "Ed25519RootGate",
    "EvidenceChain",
    "InputEnvelope",
    "MandateClaims",
    "SharedChannelObservation",
    "VerificationResult",
    "classify_action",
    "classify_input",
]
