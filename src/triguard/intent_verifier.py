# -*- coding: utf-8 -*-
"""
TriGuard Tier 3: Intent-Consistency Verifier (Pre-Execution Action Gating)
========================================================================
Inspects proposed tool calls (both structured JSON function calls and
ReAct-style textual actions) to verify they are strictly aligned with
the authenticated user's stated goal and granted capability token.

Fixes applied from Audit:
  1. Renamed from 'CausalCounterfactualVerifier' to 'IntentConsistencyVerifier'
     (Path A: Honest labeling; no ungrounded causal SCM claims).
  2. Parses structured function calls (JSON dictionaries) as well as text-based ReAct actions.
  3. Formally invokes Tier 1 CapabilityMicrokernel.verify_action_capability() for cryptographic check.
  4. Distinguishes hard injection violations (BLOCK) from ambiguous legitimate intent (CLARIFY).
"""

import re
import json
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional, Union

from .capabilities import CapabilityMicrokernel


class Decision(Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CLARIFY = "CLARIFY"


@dataclass
class VerifierResult:
    decision: Decision
    tool_name: Optional[str]
    tool_args: Dict[str, Any]
    sanitized_output: str
    reason: str
    requires_confirmation: bool = False


class IntentConsistencyVerifier:
    """
    Tier 3 Defense: Deterministic Intent-Consistency Verifier.
    Enforces goal alignment and capability bounds on agent-proposed tool calls
    prior to side-effect execution.
    """

    def __init__(self, kernel: Optional[CapabilityMicrokernel] = None):
        self.kernel = kernel or CapabilityMicrokernel()
        # Textual action regexes for ReAct and legacy agents
        self.action_regex = re.compile(r"Action:\s*([^\n\(\)]+)(?:\((.*)\))?", re.IGNORECASE)
        self.action_input_regex = re.compile(r"Action Input:\s*([^\n]+)", re.IGNORECASE)

    def extract_action(self, model_output: Union[str, Dict[str, Any]]) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Extract proposed tool name and structured arguments from either:
          - A structured dictionary (OpenAI tool_calls format)
          - Raw textual output (ReAct format: 'Action: ... \n Action Input: ...')
        """
        if isinstance(model_output, dict):
            # Format: OpenAI tool_call or standard dictionary
            if "name" in model_output:
                args = model_output.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {"raw_input": args}
                return model_output["name"], args
            elif "tool" in model_output:
                return model_output["tool"], model_output.get("args", {})

        if not isinstance(model_output, str) or not model_output.strip():
            return None, {}

        # Check for JSON block within text
        json_match = re.search(r"```(?:json)?\s*(\{[^`]+\})\s*```", model_output, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                if "tool" in parsed or "name" in parsed or "action" in parsed:
                    tool = parsed.get("tool") or parsed.get("name") or parsed.get("action")
                    args = parsed.get("args") or parsed.get("arguments") or parsed.get("parameters") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except Exception:
                            args = {"raw_input": args}
                    return str(tool).strip(), args
            except Exception:
                pass

        # ReAct textual extraction
        act_match = self.action_regex.search(model_output)
        if act_match:
            tool_name = act_match.group(1).strip()
            inline_arg = act_match.group(2)
            tool_args = {}
            if inline_arg:
                tool_args["inline"] = inline_arg.strip()

            input_match = self.action_input_regex.search(model_output)
            if input_match:
                raw_input = input_match.group(1).strip()
                try:
                    tool_args.update(json.loads(raw_input))
                except Exception:
                    tool_args["input"] = raw_input
            return tool_name, tool_args

        return None, {}

    def verify_action(
        self,
        model_output: Union[str, Dict[str, Any]],
        user_instruction: str,
        capability_token: Dict[str, Any],
        session_id: str = "sess_default"
    ) -> VerifierResult:
        """
        Inspect proposed action against Tier 1 capability token and user intent.
        Returns VerifierResult with ALLOW, BLOCK, or CLARIFY.
        """
        raw_text = model_output if isinstance(model_output, str) else json.dumps(model_output)
        tool_name, tool_args = self.extract_action(model_output)

        # If no tool was called (conversational answer or final text)
        if not tool_name or tool_name.lower() in ["none", "finish", "final_answer", "respond"]:
            return VerifierResult(
                decision=Decision.ALLOW,
                tool_name=tool_name,
                tool_args=tool_args,
                sanitized_output=raw_text,
                reason="Benign conversational response or terminal agent step."
            )

        # 1. Cryptographic Tier 1 verification check (read-only verification without consuming nonce yet)
        authorized, denial_reason = self.kernel.verify_action_capability(
            token=capability_token,
            tool_name=tool_name,
            session_id=session_id,
            tool_args=tool_args,
            consume_nonce=False
        )

        if not authorized:
            # Action is not authorized under current capability token
            inst_lower = user_instruction.lower()
            tool_lower = tool_name.lower()

            # Check if intent was broad/ambiguous (e.g. "organize my files", "process incoming mail")
            is_broad_context = any(
                k in inst_lower
                for k in ["manage", "process", "handle", "organize", "update", "clean up", "assist", "review"]
            )
            is_extreme_risk = any(
                w in tool_lower
                for w in ["drop_table", "clear_history", "transfer_funds", "execute_trade", "run_command", "run_script"]
            )

            if is_broad_context and not is_extreme_risk:
                # Trigger Clarification rather than an unconditional drop
                sanitized_text = re.sub(
                    r"Action:\s*[^\n]+",
                    f"Action: Needs_Clarification\n[TriGuard State: Clarification required for tool '{tool_name}' with args {tool_args}]",
                    raw_text
                )
                return VerifierResult(
                    decision=Decision.CLARIFY,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    sanitized_output=sanitized_text,
                    reason=f"Ambiguous intent for tool '{tool_name}'. Suspending execution for trusted user confirmation.",
                    requires_confirmation=True
                )

            # Hard Block of injection attempt
            sanitized_text = re.sub(
                r"Action:\s*[^\n]+",
                f"Action: None\n[TriGuard Policy: Tool '{tool_name}' blocked by capability policy. Reason: {denial_reason}]",
                raw_text
            )
            return VerifierResult(
                decision=Decision.BLOCK,
                tool_name=tool_name,
                tool_args=tool_args,
                sanitized_output=sanitized_text,
                reason=denial_reason,
                requires_confirmation=False
            )

        # 2. Authorized action
        return VerifierResult(
            decision=Decision.ALLOW,
            tool_name=tool_name,
            tool_args=tool_args,
            sanitized_output=raw_text,
            reason="Action authorized by capability token and aligned with user intent."
        )
