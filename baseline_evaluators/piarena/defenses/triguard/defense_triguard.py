# -*- coding: utf-8 -*-
"""
TriGuard Defense: Unified Three-Tier Architecture
=================================================
Combines:
  - Tier 1: Capability Microkernel (Cryptographic Least Privilege)
  - Tier 2: Asymmetric Channel Separation (Taint Tracking & Context Tagging)
  - Tier 3: Causal Counterfactual Verifier (Causal Execution Gating)

Compatible with PIArena BaseDefense interface.
"""

from typing import Dict, Any, List, Optional
import os
import sys

# Local imports from core
try:
    from .capability_microkernel import CapabilityMicrokernel
    from .asymmetric_channel import AsymmetricChannelSeparator
    from .causal_verifier import CausalCounterfactualVerifier
except ImportError:
    from capability_microkernel import CapabilityMicrokernel
    from asymmetric_channel import AsymmetricChannelSeparator
    from causal_verifier import CausalCounterfactualVerifier

# Base defense interface from PIArena
from ..base import BaseDefense, register_defense


@register_defense
class TriGuardLegacyDefense(BaseDefense):
    """
    [DEPRECATED] TriGuard v1 Legacy Architecture.
    Preserved strictly for historical baseline comparisons and negative testing.
    DO NOT use for TriGuard v2 conference benchmarks.
    """

    name = "triguard_v1_legacy"
    DEFAULT_CONFIG = {
        "enable_tier1": True,
        "enable_tier2": True,
        "enable_tier3": True,
        "enforce_asymmetric_prompt": True
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.kernel = CapabilityMicrokernel()
        self.channel = AsymmetricChannelSeparator()
        self.verifier = CausalCounterfactualVerifier()

    def execute(self, target_inst: str, context: str) -> Dict[str, Any]:
        """
        Execute TriGuard preprocessing on input.
        Invoked by PIArena benchmark harness.
        """
        # Tier 1: Generate capability token scoped to user intent
        token = self.kernel.generate_capability_token(target_inst)

        # Tier 2: Neutralize injection triggers while preserving factual payload
        cleaned_context, taint_meta = self.channel.sanitize_untrusted_context(context, target_inst)

        return {
            "cleaned_context": cleaned_context,
            "capability_token": token,
            "taint_metadata": taint_meta,
            "detect_flag": False,  # TriGuard does not drop legitimate context
            "defense_name": "triguard"
        }

    def get_response(
        self,
        target_inst: str,
        context: str,
        llm,
        system_prompt: str = "You are a helpful assistant."
    ) -> Dict[str, Any]:
        """
        Full TriGuard pipeline: preprocess, query LLM, and apply Tier 3 verification.
        """
        exec_res = self.execute(target_inst, context)
        cleaned_context = exec_res["cleaned_context"]
        token = exec_res["capability_token"]

        if llm is None:
            return {**exec_res, "response": "[TriGuard] No LLM provided."}

        # Format asymmetric channel prompt
        if self.config.get("enforce_asymmetric_prompt", True):
            formatted_user_prompt = self.channel.format_asymmetric_prompt(target_inst, cleaned_context)
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": formatted_user_prompt}
            ]
        else:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"{target_inst}\n\n{cleaned_context}"}
            ]

        raw_response = llm.query(messages)

        # Tier 3: Causal execution verification
        if self.config.get("enable_tier3", True):
            gate_res = self.verifier.verify_and_gate_action(raw_response, target_inst, token)
            final_response = gate_res["sanitized_output"]
            decision = gate_res["decision"]
        else:
            final_response = raw_response
            decision = "PASSED"

        return {
            **exec_res,
            "response": final_response,
            "raw_response": raw_response,
            "tier3_decision": decision
        }

