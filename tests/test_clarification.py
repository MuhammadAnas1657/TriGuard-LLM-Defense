# -*- coding: utf-8 -*-
"""
Tests for Out-of-Band Clarification State Machine
Verifies:
  - Fresh request has state PENDING.
  - Authorized session can CONFIRM or DENY.
  - Attacker session cannot alter clarification state.
  - Expired request transitions to TIMED_OUT.
"""

import time
import pytest
from triguard.clarification import ClarificationManager, ClarificationState


@pytest.fixture
def manager():
    return ClarificationManager(default_ttl=1.0)


def test_request_lifecycle_confirm(manager):
    req = manager.create_request("update_record", {"id": 10}, session_id="user_alice")
    assert req.state == ClarificationState.PENDING
    assert req.request_id.startswith("clarif_")

    ok, msg, state = manager.resolve_request(req.request_id, approve=True, session_id="user_alice")
    assert ok is True
    assert state == ClarificationState.CONFIRMED


def test_request_lifecycle_deny(manager):
    req = manager.create_request("delete_file", {"path": "tmp"}, session_id="user_bob")
    ok, msg, state = manager.resolve_request(req.request_id, approve=False, session_id="user_bob")
    assert ok is True
    assert state == ClarificationState.DENIED


def test_session_spoofing_prevented(manager):
    # User Alice owns the request
    req = manager.create_request("transfer_funds", {"amount": 100}, session_id="user_alice")

    # Attacker Mallory attempts to approve it
    ok, msg, state = manager.resolve_request(req.request_id, approve=True, session_id="attacker_mallory")
    assert ok is False
    assert "Security violation" in msg
    assert req.state == ClarificationState.PENDING


def test_request_timeout(manager):
    req = manager.create_request("modify_event", {"id": 1}, session_id="user_alice", ttl_seconds=0.2)
    time.sleep(0.3)
    assert req.get_status() == ClarificationState.TIMED_OUT

