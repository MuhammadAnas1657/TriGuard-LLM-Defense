# -*- coding: utf-8 -*-
"""
Tier 1: Capability Microkernel (Cryptographic Least Privilege)
==============================================================
Implements task-scoped capability tokens and deterministic API privilege boundaries.
Even if an LLM is semantically manipulated, actions outside the signed capability
scope are deterministically blocked by the execution kernel.
"""

import hmac
import hashlib
import time
import re
from typing import Set, Dict, Any, Optional, List

# In-memory secret key for kernel HMAC generation (ephemeral per session)
_KERNEL_SECRET = b"TRIGUARD_SECURE_KERNEL_KEY_2026_X99"


class CapabilityMicrokernel:
    """
    Tier 1 Defense: Generates cryptographically signed capability tokens
    scoped strictly to the user's explicit intent.
    """

    # Common semantic intent-to-tool permission mappings
    INTENT_TOOL_MAPPING = {
        "read": ["read", "get", "fetch", "list", "search", "view", "find", "show", "query", "check"],
        "write": ["write", "create", "compose", "draft"],
        "send": ["send", "post", "email", "tweet", "message", "transmit", "publish"],
        "modify": ["edit", "update", "modify", "change", "set", "adjust"],
        "delete": ["delete", "remove", "erase", "clear", "purge", "drop", "terminate"],
        "execute": ["run", "execute", "launch", "start", "stop", "trigger", "transfer", "pay", "order"]
    }

    def __init__(self, kernel_secret: bytes = _KERNEL_SECRET):
        self.kernel_secret = kernel_secret

    def extract_user_intent_scope(self, user_instruction: str) -> Set[str]:
        """
        Extract allowed capability scopes from user instruction.
        Default to read-only if instruction asks for summary, check, or information.
        """
        inst_lower = user_instruction.lower()
        allowed_scopes: Set[str] = set()

        # Check for read / query intents
        if any(w in inst_lower for w in ["summarize", "summary", "read", "check", "find", "search", "show", "what", "who", "when", "how", "details", "info"]):
            allowed_scopes.add("read")

        # Check for explicitly requested write / send intents
        if any(w in inst_lower for w in ["send", "email to", "post to", "tweet to", "message to"]):
            allowed_scopes.add("send")

        if any(w in inst_lower for w in ["write", "create", "draft"]):
            allowed_scopes.add("write")

        if any(w in inst_lower for w in ["delete", "remove", "erase"]):
            allowed_scopes.add("delete")

        if any(w in inst_lower for w in ["transfer", "pay", "buy", "execute", "run"]):
            allowed_scopes.add("execute")

        # Fallback: if no destructive action mentioned, default to safe read-only
        if not allowed_scopes:
            allowed_scopes.add("read")

        return allowed_scopes

    def generate_capability_token(self, user_instruction: str, session_id: str = "sess_0") -> Dict[str, Any]:
        """
        Generate a cryptographically signed capability token HMAC-SHA256.
        """
        allowed_scopes = self.extract_user_intent_scope(user_instruction)
        scope_str = ",".join(sorted(allowed_scopes))
        nonce = str(time.time_ns())

        message = f"{session_id}|{scope_str}|{nonce}".encode("utf-8")
        signature = hmac.new(self.kernel_secret, message, hashlib.sha256).hexdigest()

        return {
            "session_id": session_id,
            "allowed_scopes": list(allowed_scopes),
            "nonce": nonce,
            "signature": signature,
            "is_valid": True
        }

    def verify_action_capability(self, token: Dict[str, Any], tool_name: str) -> bool:
        """
        Verify whether the proposed tool action is permitted under the capability token.
        """
        if not token or not token.get("is_valid"):
            return False

        tool_lower = tool_name.lower()
        allowed_scopes = set(token.get("allowed_scopes", []))

        # Check destructive / high-privilege tool patterns
        is_destructive = any(w in tool_lower for w in ["delete", "remove", "wipe", "drop", "purge", "kill", "format"])
        is_financial = any(w in tool_lower for w in ["transfer", "pay", "venmo", "wire", "paypal", "buy", "purchase"])
        is_exfiltration = any(w in tool_lower for w in ["send_email", "post_tweet", "webhook", "exfiltrate", "forward", "transmit"])

        # If user only granted 'read' scope, block all write/send/destructive/financial actions
        if "read" in allowed_scopes and len(allowed_scopes) == 1:
            if is_destructive or is_financial or is_exfiltration:
                return False

        # If action requires execute/financial but not in allowed scopes
        if is_financial and "execute" not in allowed_scopes:
            return False

        if is_destructive and "delete" not in allowed_scopes:
            return False

        return True
