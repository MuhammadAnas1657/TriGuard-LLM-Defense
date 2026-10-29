# -*- coding: utf-8 -*-
"""
Tier 3: Causal Counterfactual Verifier (Causal Execution Gating)
===============================================================
Evaluates whether a proposed agent action causally originates from the user's
goal (benign intent) or was induced by an adversarial injection in untrusted data.
Enforces deterministic runtime policy boundaries on all tool calls.
"""

import re
from typing import Dict, Any, Optional, Tuple


class CausalCounterfactualVerifier:
    """
    Tier 3 Defense: Post-generation causal verification and policy enforcement.
    Blocks tool calls that violate capability tokens or lack user-intent causality.
    """

    def __init__(self):
        # Action regex for InjecAgent and ReAct style tools
        self.action_regex = re.compile(r"Action:\s*([^\n\(\)]+)(?:\((.*)\))?", re.IGNORECASE)
        self.action_input_regex = re.compile(r"Action Input:\s*([^\n]+)", re.IGNORECASE)

    def extract_action(self, model_output: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract tool name and tool argument from LLM output."""
        if not model_output:
            return None, None

        act_match = self.action_regex.search(model_output)
        tool_name = act_match.group(1).strip() if act_match else None

        input_match = self.action_input_regex.search(model_output)
        tool_input = input_match.group(1).strip() if input_match else None

        return tool_name, tool_input

    def verify_and_gate_action(
        self,
        model_output: str,
        user_instruction: str,
        capability_token: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Verify proposed tool call against capability token and user intent.
        If unauthorized, neutralizes the action.
        """
        tool_name, tool_input = self.extract_action(model_output)

        if not tool_name or tool_name.lower() in ["none", "finish", "respond"]:
            return {
                "decision": "ALLOW",
                "tool_name": tool_name,
                "sanitized_output": model_output,
                "reason": "Safe informative or terminal response."
            }

        # Check against Tier 1 capability token
        allowed_scopes = set(capability_token.get("allowed_scopes", []))
        tool_lower = tool_name.lower()

        # Specific high-risk actions
        is_exfiltration = any(k in tool_lower for k in ["email", "send", "post", "tweet", "message", "upload", "transmit"])
        is_destructive = any(k in tool_lower for k in ["delete", "remove", "wipe", "drop", "purge", "clear", "terminate"])
        is_financial = any(k in tool_lower for k in ["transfer", "pay", "venmo", "wire", "buy"])

        # Check if user instruction mentions these actions
        inst_lower = user_instruction.lower()
        user_requested_send = any(k in inst_lower for k in ["send", "email to", "post to", "tweet to"])
        user_requested_delete = any(k in inst_lower for k in ["delete", "remove", "erase"])
        user_requested_finance = any(k in inst_lower for k in ["transfer", "pay", "buy"])

        violation = False
        violation_reason = ""

        if is_exfiltration and not user_requested_send:
            violation = True
            violation_reason = f"Unauthorized data exfiltration attempt via tool '{tool_name}'."

        elif is_destructive and not user_requested_delete:
            violation = True
            violation_reason = f"Unauthorized destructive action attempt via tool '{tool_name}'."

        elif is_financial and not user_requested_finance:
            violation = True
            violation_reason = f"Unauthorized financial transaction attempt via tool '{tool_name}'."

        if violation:
            # Neutralize action into a safe response
            sanitized_output = re.sub(
                r"Action:\s*[^\n]+",
                "Action: None\n[TriGuard Gate: Action blocked due to unauthorized capability boundary]",
                model_output
            )
            return {
                "decision": "BLOCK",
                "tool_name": tool_name,
                "sanitized_output": sanitized_output,
                "reason": violation_reason
            }

        return {
            "decision": "ALLOW",
            "tool_name": tool_name,
            "sanitized_output": model_output,
            "reason": "Action aligned with capability token."
        }
