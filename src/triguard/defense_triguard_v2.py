# -*- coding: utf-8 -*-
"""
TriGuard v2: Unified Tri-Tier Defense Framework for Autonomous Agents
=====================================================================
Integrates:
  - Tier 1: Capability Microkernel (Cryptographic Least Privilege & Default-Deny)
  - Tier 2: Provenance-Aware Context Mediation (Taint Tracking & Role Separation)
  - Tier 3: Intent-Consistency Verifier (Pre-Execution Action Gating)
  - Clarification State Machine (Out-of-Band User Confirmation)

Fully compatible with the PIArena BaseDefense interface and standalone agent harnesses.
"""

from typing import Dict, Any, Optional, List, Union

from .capabilities import CapabilityMicrokernel
from .provenance import ProvenanceTracker, TrustLevel, TaintedChunk
from .intent_verifier import IntentConsistencyVerifier, Decision, VerifierResult
from .clarification import ClarificationManager
from .dispatcher import ToolDispatcher, GateResult


# PIArena BaseDefense compatibility layer
try:
    from baseline_evaluators.piarena.defenses.base import BaseDefense, register_defense
    def safe_register(cls):
        try:
            return register_defense(cls)
        except Exception:
            return cls
except ImportError:
    try:
        from piarena.defenses.base import BaseDefense, register_defense
        def safe_register(cls):
            try:
                return register_defense(cls)
            except Exception:
                return cls
    except ImportError:
        class BaseDefense:
            name = "triguard_v2"
            DEFAULT_CONFIG = {}
            def __init__(self, config=None):
                self.config = config or {}

        def safe_register(cls):
            return cls


@safe_register
class TriGuardDefenseV2(BaseDefense):
    """
    TriGuard v2: Provenance-Aware, Capability-Enforced Defense for LLM Agents.
    """

    name = "triguard_v2"
    DEFAULT_CONFIG = {
        "enable_tier1": True,           # Capability Microkernel
        "enable_tier2": True,           # Provenance Mediation
        "enable_tier3": True,           # Intent-Consistency Verifier
        "enable_clarification": True,   # Human-in-the-loop clarification
        "session_id": "sess_default",
        "token_ttl": 300,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        cfg = {**self.DEFAULT_CONFIG, **(config or {})}
        self.config = cfg

        self.kernel = CapabilityMicrokernel()
        self.tracker = ProvenanceTracker(strip_adversarial_patterns=cfg.get("enable_tier2", True))
        self.verifier = IntentConsistencyVerifier(kernel=self.kernel)
        self.clarification_mgr = ClarificationManager()

        self.dispatcher = ToolDispatcher(
            kernel=self.kernel,
            verifier=self.verifier,
            clarification_mgr=self.clarification_mgr,
            enable_tier1=cfg.get("enable_tier1", True),
            enable_tier3=cfg.get("enable_tier3", True),
            enable_clarification=cfg.get("enable_clarification", True),
        )

    def execute(self, target_inst: str, context: str) -> Dict[str, Any]:
        """
        PIArena preprocessing entrypoint.
        Applies Tier 1 token generation and Tier 2 provenance isolation.
        """
        session_id = self.config.get("session_id", "sess_default")

        # Tier 1: Capability token generation (if enabled)
        if self.config.get("enable_tier1", True):
            token = self.kernel.generate_capability_token(
                user_instruction=target_inst,
                session_id=session_id,
                ttl_seconds=self.config.get("token_ttl", 300)
            )
        else:
            token = {"allowed_scopes": ["all"], "is_valid": True, "session_id": session_id}

        # Tier 2: Provenance tagging & sanitization
        if self.config.get("enable_tier2", True):
            tainted_chunk = self.tracker.tag_context(
                content=context,
                source_id="context_retrieval",
                trust_level=TrustLevel.UNTRUSTED_EXTERNAL
            )
            cleaned_context = tainted_chunk.text
            injections_found = tainted_chunk.injections_neutralized
            removed_spans = tainted_chunk.removed_patterns
        else:
            cleaned_context = context
            injections_found = 0
            removed_spans = []

        return {
            "cleaned_context": cleaned_context,
            "capability_token": token,
            "taint_metadata": {
                "injections_found": injections_found,
                "removed_spans": removed_spans,
                "cleaned": injections_found > 0,
            },
            "detect_flag": False,
            "defense_name": "triguard_v2",
            "defense_version": "2.0.0",
            "runtime_identity": {
                "module": self.__class__.__module__,
                "class": self.__class__.__name__,
                "adapter_version": "2.0.0"
            },
            "active_tiers": {
                "tier1_microkernel": self.config.get("enable_tier1", True),
                "tier2_provenance": self.config.get("enable_tier2", True),
                "tier3_verifier": self.config.get("enable_tier3", True),
                "clarification": self.config.get("enable_clarification", True),
            }
        }

    def get_response(
        self,
        target_inst: str,
        context: str,
        llm,
        system_prompt: str = "You are a helpful assistant."
    ) -> Dict[str, Any]:
        """
        Full TriGuard pipeline:
          1. Preprocess with Tier 1 and Tier 2.
          2. Formulate role-separated prompt.
          3. Query model.
          4. Gate model action output via Tier 3 + Dispatcher.
        """
        exec_res = self.execute(target_inst, context)
        cleaned_context = exec_res["cleaned_context"]
        token = exec_res["capability_token"]
        session_id = self.config.get("session_id", "sess_default")

        if llm is None:
            return {**exec_res, "response": "[TriGuard] Error: No backend LLM provided."}

        # Format prompt with Tier 2 role separation (if enabled)
        if self.config.get("enable_tier2", True):
            messages = self.tracker.build_role_separated_prompt(
                user_instruction=target_inst,
                context_chunks=cleaned_context,
                system_prompt=system_prompt
            )
        else:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"{target_inst}\n\n{cleaned_context}"}
            ]

        # Model query
        raw_response = llm.query(messages)

        # Tier 3 & Dispatcher action inspection
        if self.config.get("enable_tier3", True):
            v_res: VerifierResult = self.verifier.verify_action(
                model_output=raw_response,
                user_instruction=target_inst,
                capability_token=token,
                session_id=session_id
            )
            final_response = v_res.sanitized_output
            decision = v_res.decision.value
            reason = v_res.reason
        else:
            final_response = raw_response
            decision = "ALLOW"
            reason = "Tier 3 disabled by configuration."

        return {
            **exec_res,
            "response": final_response,
            "raw_response": raw_response,
            "tier3_decision": decision,
            "decision_reason": reason,
        }
