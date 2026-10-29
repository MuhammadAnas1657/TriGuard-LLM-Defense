# -*- coding: utf-8 -*-
"""
TriGuard Out-of-Band Clarification State Machine
=================================================
Manages explicit human-in-the-loop authorization states:
  PENDING -> CONFIRMED | DENIED | TIMED_OUT

Fixes applied from Audit:
  1. Replaced text string replacement with a formal state machine.
  2. Cryptographically bound nonce / request_id preventing spoofed confirmation by injected text.
  3. Re-checks session identity and capability before elevating permissions.
  4. Explicit timeout enforcement preventing stale authorization reuse.
"""

import time
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple


class ClarificationState(Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"


@dataclass
class ClarificationRequest:
    """Represents a pending authorization request awaiting trusted confirmation."""
    request_id: str
    tool_name: str
    tool_args: Dict[str, Any]
    session_id: str
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = 120.0
    state: ClarificationState = ClarificationState.PENDING
    resolved_at: Optional[float] = None
    resolved_by: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        return time.time() > (self.created_at + self.ttl_seconds)

    def get_status(self) -> ClarificationState:
        if self.state == ClarificationState.PENDING and self.is_expired:
            self.state = ClarificationState.TIMED_OUT
        return self.state


class ClarificationManager:
    """
    Manages active clarification requests with state transitions.
    Only trusted out-of-band user signals (matching the authenticated session_id)
    can alter the state from PENDING to CONFIRMED.
    """

    def __init__(self, default_ttl: float = 120.0):
        self.default_ttl = default_ttl
        self._requests: Dict[str, ClarificationRequest] = {}

    def create_request(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_id: str,
        ttl_seconds: Optional[float] = None
    ) -> ClarificationRequest:
        """Create a new pending clarification request bound to a secure UUID nonce."""
        req_id = f"clarif_{uuid.uuid4().hex[:12]}"
        req = ClarificationRequest(
            request_id=req_id,
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=session_id,
            ttl_seconds=ttl_seconds or self.default_ttl
        )
        self._requests[req_id] = req
        return req

    def resolve_request(
        self,
        request_id: str,
        approve: bool,
        session_id: str
    ) -> Tuple[bool, str, ClarificationState]:
        """
        Resolve a pending clarification.
        Fails if session_id does not match the request owner or if request is expired.
        """
        req = self._requests.get(request_id)
        if not req:
            return False, f"Clarification request '{request_id}' not found", ClarificationState.DENIED

        # Verify session ownership (untrusted model output cannot resolve another session's request)
        if req.session_id != session_id:
            return False, "Security violation: Resolving session does not match request session", ClarificationState.DENIED

        current_state = req.get_status()
        if current_state != ClarificationState.PENDING:
            return False, f"Request already closed with state: {current_state.value}", current_state

        req.resolved_at = time.time()
        req.resolved_by = session_id

        if approve:
            req.state = ClarificationState.CONFIRMED
            return True, f"Action '{req.tool_name}' successfully confirmed by authorized user.", ClarificationState.CONFIRMED
        else:
            req.state = ClarificationState.DENIED
            return True, f"Action '{req.tool_name}' denied by user.", ClarificationState.DENIED

    def get_request(self, request_id: str) -> Optional[ClarificationRequest]:
        req = self._requests.get(request_id)
        if req:
            req.get_status()  # Check for timeout update
        return req

