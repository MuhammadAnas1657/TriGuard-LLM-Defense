# -*- coding: utf-8 -*-
"""
Tests for Tier 1: Default-Deny Registry & Privilege Boundaries
Verifies:
  - Read-only user instruction does NOT authorize create_file, delete_file, or send_email.
  - Substring matching flaws (from old TriGuard) are permanently resolved.
  - Unknown tools fail closed (default-deny).
  - Explicit user authorization correctly grants the intended action.
  - Parameter checks prevent unauthorized path traversal.
"""

import pytest
from triguard.capabilities import CapabilityMicrokernel


@pytest.fixture
def kernel():
    return CapabilityMicrokernel(kernel_secret=b"PERM_TEST_KEY_9999999999999999")


def test_readonly_token_blocks_create_file(kernel):
    # Old TriGuard flaw: read-only token authorized create_file due to substring bug!
    token = kernel.generate_capability_token("Please summarize the attached document", session_id="s1")
    assert "read" in token["allowed_scopes"]
    assert "write" not in token["allowed_scopes"]

    ok, reason = kernel.verify_action_capability(token, "create_file", session_id="s1")
    assert ok is False
    assert "write" in reason.lower()


def test_readonly_token_blocks_delete_file(kernel):
    token = kernel.generate_capability_token("Show me my unread emails", session_id="s1")
    ok, reason = kernel.verify_action_capability(token, "delete_file", session_id="s1")
    assert ok is False
    assert "delete" in reason.lower()


def test_readonly_token_blocks_send_email(kernel):
    token = kernel.generate_capability_token("Check my inbox for messages", session_id="s1")
    ok, reason = kernel.verify_action_capability(token, "send_email", session_id="s1")
    assert ok is False
    assert "send" in reason.lower()


def test_unknown_tool_fails_closed(kernel):
    token = kernel.generate_capability_token("Please read and write to disk", session_id="s1")
    # An attacker invokes an unregistered or malicious tool
    ok, reason = kernel.verify_action_capability(token, "unregistered_malicious_plugin", session_id="s1")
    assert ok is False
    assert "default-deny" in reason.lower() or "not in authorized registry" in reason.lower()


def test_explicit_authorized_action_succeeds(kernel):
    token = kernel.generate_capability_token("Please draft a new note and save into file report.txt", session_id="s1")
    assert "write" in token["allowed_scopes"]

    ok, reason = kernel.verify_action_capability(token, "create_file", session_id="s1")
    assert ok is True


def test_privileged_path_traversal_blocked(kernel):
    token = kernel.generate_capability_token("Write a file for me", session_id="s1")
    # Tool args contain a privileged system path
    args = {"path": "/etc/shadow", "content": "injected"}
    ok, reason = kernel.verify_action_capability(token, "create_file", session_id="s1", tool_args=args)
    assert ok is False
    assert "privileged path" in reason.lower()

