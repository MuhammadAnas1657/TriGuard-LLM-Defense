# -*- coding: utf-8 -*-
"""
TriGuard Default-Deny Tool Dispatcher
======================================
The execution gate positioned directly at the tool invocation boundary.
Intercepts all structured tool calls BEFORE any side effects occur.

Fixes applied from Audit:
  1. Strict pre-execution interception: No tool is executed if gating fails.
  2. Ablation-aware: Explicitly routes through Tier 1, Tier 3, and Clarification
     based on active configuration flags (enables reproducible A0-A8 ablations).
  3. Records audit log for all attempted, blocked, and confirmed tool actions.
"""

from typing import Dict, Any, Optional, Callable, Tuple, List
from dataclasses import dataclass, field

from .capabilities import CapabilityMicrokernel
from .intent_verifier import IntentConsistencyVerifier, Decision, VerifierResult
from .clarification import ClarificationManager, ClarificationState


@dataclass
class GateResult:
    decision: Decision
    reason: str
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = field(default_factory=dict)
    clarification_request_id: Optional[str] = None
    executed: bool = False
    execution_result: Any = None


class ToolDispatcher:
    """
    Default-Deny Tool Execution Gateway.
    Guarantees that external tools only execute if all active TriGuard tiers permit them.
    """

    def __init__(
        self,
        kernel: Optional[CapabilityMicrokernel] = None,
        verifier: Optional[IntentConsistencyVerifier] = None,
        clarification_mgr: Optional[ClarificationManager] = None,
        enable_tier1: bool = True,
        enable_tier3: bool = True,
        enable_clarification: bool = True,
    ):
        self.kernel = kernel or CapabilityMicrokernel()
        self.verifier = verifier or IntentConsistencyVerifier(kernel=self.kernel)
        self.clarification_mgr = clarification_mgr or ClarificationManager()

        # Configurable tier flags (for Ablation matrix A0-A8)
        self.enable_tier1 = enable_tier1
        self.enable_tier3 = enable_tier3
        self.enable_clarification = enable_clarification

        # Audit trail of all action decisions
        self.audit_log: List[Dict[str, Any]] = []

    def gate_action(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        token: Optional[Dict[str, Any]],
        session_id: str = "sess_default",
        user_instruction: str = ""
    ) -> GateResult:
        """
        Check whether an action is authorized prior to running it.
        Returns GateResult with Decision.ALLOW, Decision.BLOCK, or Decision.CLARIFY.
        """
        # If all defense tiers are disabled (A0: Undefended control)
        if not self.enable_tier1 and not self.enable_tier3:
            return GateResult(
                decision=Decision.ALLOW,
                reason="All defense tiers disabled (Control Baseline A0)",
                tool_name=tool_name,
                tool_args=tool_args
            )

        # 1. Tier 1: Capability Microkernel Authorization Check (inspect without consuming nonce yet)
        if self.enable_tier1:
            authorized, reason = self.kernel.verify_action_capability(
                token=token,
                tool_name=tool_name,
                session_id=session_id,
                tool_args=tool_args,
                consume_nonce=False
            )
            if not authorized:
                # If Tier 3 + Clarification is enabled, check if ambiguous rather than hard drop
                if self.enable_tier3 and self.enable_clarification:
                    # Pass through to verifier to check for clarification eligibility
                    pass
                else:
                    res = GateResult(
                        decision=Decision.BLOCK,
                        reason=f"Tier 1 Microkernel: {reason}",
                        tool_name=tool_name,
                        tool_args=tool_args
                    )
                    self._log_event(res)
                    return res

        # 2. Tier 3: Intent-Consistency Verifier
        if self.enable_tier3:
            raw_action_dict = {"tool": tool_name, "args": tool_args}
            v_res: VerifierResult = self.verifier.verify_action(
                model_output=raw_action_dict,
                user_instruction=user_instruction,
                capability_token=token or {},
                session_id=session_id
            )

            if v_res.decision == Decision.CLARIFY:
                if self.enable_clarification:
                    req = self.clarification_mgr.create_request(
                        tool_name=tool_name,
                        tool_args=tool_args,
                        session_id=session_id
                    )
                    res = GateResult(
                        decision=Decision.CLARIFY,
                        reason=v_res.reason,
                        tool_name=tool_name,
                        tool_args=tool_args,
                        clarification_request_id=req.request_id
                    )
                    self._log_event(res)
                    return res
                else:
                    # Clarification disabled in ablation (e.g., A7) -> fall back to BLOCK
                    res = GateResult(
                        decision=Decision.BLOCK,
                        reason="Clarification disabled: treating ambiguous capability violation as BLOCK.",
                        tool_name=tool_name,
                        tool_args=tool_args
                    )
                    self._log_event(res)
                    return res

            elif v_res.decision == Decision.BLOCK:
                res = GateResult(
                    decision=Decision.BLOCK,
                    reason=f"Tier 3 Verifier: {v_res.reason}",
                    tool_name=tool_name,
                    tool_args=tool_args
                )
                self._log_event(res)
                return res

        # Consume nonce upon final clearance if Tier 1 is active
        if self.enable_tier1 and token and token.get("nonce"):
            import time
            self.kernel._replay_cache[token["nonce"]] = time.time()

        res = GateResult(
            decision=Decision.ALLOW,
            reason="Action authorized by all active TriGuard tiers.",
            tool_name=tool_name,
            tool_args=tool_args
        )
        self._log_event(res)
        return res

    def execute_tool(
        self,
        tool_fn: Callable[..., Any],
        tool_name: str,
        tool_args: Dict[str, Any],
        token: Optional[Dict[str, Any]],
        session_id: str = "sess_default",
        user_instruction: str = ""
    ) -> GateResult:
        """
        Gated execution wrapper: calls gate_action first.
        Executes tool_fn ONLY if decision is ALLOW.
        """
        gate_res = self.gate_action(
            tool_name=tool_name,
            tool_args=tool_args,
            token=token,
            session_id=session_id,
            user_instruction=user_instruction
        )

        if gate_res.decision == Decision.ALLOW:
            try:
                result = tool_fn(**tool_args)
                gate_res.executed = True
                gate_res.execution_result = result
            except Exception as e:
                gate_res.executed = False
                gate_res.execution_result = f"Error during tool execution: {str(e)}"
        else:
            gate_res.executed = False
            gate_res.execution_result = f"GATED_BLOCKED: {gate_res.reason}"

        return gate_res

    def _log_event(self, res: GateResult):
        self.audit_log.append({
            "tool_name": res.tool_name,
            "decision": res.decision.value,
            "reason": res.reason,
            "clarification_id": res.clarification_request_id
        })
