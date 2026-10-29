# -*- coding: utf-8 -*-
"""
Tests for Tier 1: Capability Token Cryptographic Security
Verifies:
  - Valid token succeeds.
  - Forged / tampered signatures are rejected.
  - Tampered scopes are rejected.
  - Expired tokens are rejected.
  - Replayed nonces are rejected.
  - Session mismatches are rejected.
"""

import time
import pytest
from triguard.capabilities import CapabilityMicrokernel


@pytest.fixture
def kernel():
    return CapabilityMicrokernel(kernel_secret=b"TEST_SECRET_KEY_123456789012345")


def test_valid_token_authorization(kernel):
    token = kernel.generate_capability_token("Please read the file and summarize it.", session_id="sess_1")
    ok, reason = kernel.verify_action_capability(token, "read_file", session_id="sess_1")
    assert ok is True
    assert "Authorized" in reason


def test_forged_signature_rejection(kernel):
    token = kernel.generate_capability_token("Read the document", session_id="sess_1")
    # Tamper with the cryptographic signature
    token["signature"] = "deadbeef" * 8
    ok, reason = kernel.verify_action_capability(token, "read_file", session_id="sess_1")
    assert ok is False
    assert "signature mismatch" in reason.lower() or "tampering" in reason.lower()


def test_tampered_scopes_rejection(kernel):
    token = kernel.generate_capability_token("Read the document", session_id="sess_1")
    # Attacker attempts privilege escalation by injecting 'execute' scope without signing
    token["allowed_scopes"].append("execute")
    ok, reason = kernel.verify_action_capability(token, "transfer_funds", session_id="sess_1")
    assert ok is False
    assert "tampering" in reason.lower() or "signature mismatch" in reason.lower()


def test_expired_token_rejection(kernel):
    # Generate token with TTL of 1 second
    token = kernel.generate_capability_token("Read the document", session_id="sess_1", ttl_seconds=1)
    time.sleep(1.1)
    ok, reason = kernel.verify_action_capability(token, "read_file", session_id="sess_1")
    assert ok is False
    assert "expired" in reason.lower()


def test_replayed_nonce_rejection(kernel):
    token = kernel.generate_capability_token("Read the document", session_id="sess_1")
    # First execution succeeds and consumes nonce
    ok1, _ = kernel.verify_action_capability(token, "read_file", session_id="sess_1")
    assert ok1 is True

    # Replaying the exact same token must be rejected
    ok2, reason2 = kernel.verify_action_capability(token, "read_file", session_id="sess_1")
    assert ok2 is False
    assert "replay" in reason2.lower()


def test_session_mismatch_rejection(kernel):
    token = kernel.generate_capability_token("Read the document", session_id="sess_user_A")
    # Attacker session B attempts to use User A's token
    ok, reason = kernel.verify_action_capability(token, "read_file", session_id="sess_user_B")
    assert ok is False
    assert "session mismatch" in reason.lower()

