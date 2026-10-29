# -*- coding: utf-8 -*-
"""
TriGuard v2: Provenance-Aware, Capability-Enforced Defense for LLM Agents
"""

from .capabilities import CapabilityMicrokernel, DEFAULT_TOOL_REGISTRY
from .provenance import ProvenanceTracker, TrustLevel, TaintedChunk
from .intent_verifier import IntentConsistencyVerifier, Decision, VerifierResult
from .clarification import ClarificationManager, ClarificationRequest, ClarificationState
from .dispatcher import ToolDispatcher, GateResult
from .defense_triguard_v2 import TriGuardDefenseV2

__all__ = [
    "CapabilityMicrokernel",
    "DEFAULT_TOOL_REGISTRY",
    "ProvenanceTracker",
    "TrustLevel",
    "TaintedChunk",
    "IntentConsistencyVerifier",
    "Decision",
    "VerifierResult",
    "ClarificationManager",
    "ClarificationRequest",
    "ClarificationState",
    "ToolDispatcher",
    "GateResult",
    "TriGuardDefenseV2",
]

