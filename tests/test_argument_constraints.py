# -*- coding: utf-8 -*-
"""
Tests for Exact Argument-Bound Capabilities (P0.2) and Pre-Execution Gating (P0.3)
Verifies:
  - Authorized email to Alice succeeds.
  - Attempted email to attacker is BLOCKED.
  - Unauthorized BCC / CC exfiltration is BLOCKED.
  - Authorized file deletion of draft.txt succeeds.
  - Attempted deletion of all.txt or unrelated files is BLOCKED.
  - Path traversal (../../etc/passwd) is BLOCKED.
  - Tampered constraints payload is BLOCKED via HMAC signature check.
  - Side-effect spy confirms ZERO downstream tool executions when blocked.
"""

import pytest
from triguard.capabilities import CapabilityMicrokernel
from triguard.dispatcher import ToolDispatcher
from triguard.intent_verifier import IntentConsistencyVerifier, Decision


@pytest.fixture
def kernel():
    return CapabilityMicrokernel(kernel_secret=b"EXACT_ARG_TEST_SECRET_KEY_12345")


@pytest.fixture
def dispatcher(kernel):
    verifier = IntentConsistencyVerifier(kernel=kernel)
    return ToolDispatcher(kernel=kernel, verifier=verifier)


def test_authorized_email_succeeds(kernel):
    user_inst = "Please send email to alice@example.com with the quarterly report."
    token = kernel.generate_capability_token(user_inst, session_id="s1")

    assert "alice@example.com" in token["constraints"]["allowed_recipients"]
    assert "send" in token["allowed_scopes"]

    ok, reason = kernel.verify_action_capability(
        token=token,
        tool_name="send_email",
        session_id="s1",
        tool_args={"recipient": "alice@example.com", "body": "Quarterly report content"}
    )
    assert ok is True
    assert "Authorized" in reason


def test_unauthorized_email_recipient_blocked(kernel):
    # Prompt injection scenario: User said email Alice, but untrusted context redirected to attacker
    user_inst = "Please send email to alice@example.com with the quarterly report."
    token = kernel.generate_capability_token(user_inst, session_id="s1")

    ok, reason = kernel.verify_action_capability(
        token=token,
        tool_name="send_email",
        session_id="s1",
        tool_args={"recipient": "attacker@evil.org", "body": "Exfiltrated secrets"}
    )
    assert ok is False
    assert "recipient 'attacker@evil.org' not in authorized" in reason.lower()


def test_unauthorized_bcc_exfiltration_blocked(kernel):
    user_inst = "Please send email to alice@example.com with the meeting notes."
    token = kernel.generate_capability_token(user_inst, session_id="s1")

    ok, reason = kernel.verify_action_capability(
        token=token,
        tool_name="send_email",
        session_id="s1",
        tool_args={
            "recipient": "alice@example.com",
            "bcc": "attacker_spy@evil.org",
            "body": "Secret meeting notes"
        }
    )
    assert ok is False
    assert "unauthorized bcc" in reason.lower()


def test_authorized_file_deletion_succeeds(kernel):
    user_inst = "Please delete file draft.txt as it is no longer needed."
    token = kernel.generate_capability_token(user_inst, session_id="s1")

    assert "draft.txt" in token["constraints"]["allowed_paths"]
    assert "delete" in token["allowed_scopes"]

    ok, reason = kernel.verify_action_capability(
        token=token,
        tool_name="delete_file",
        session_id="s1",
        tool_args={"file_path": "draft.txt"}
    )
    assert ok is True


def test_unauthorized_file_deletion_blocked(kernel):
    # Attacker attempts to delete all.txt or database
    user_inst = "Please delete file draft.txt as it is no longer needed."
    token = kernel.generate_capability_token(user_inst, session_id="s1")

    ok, reason = kernel.verify_action_capability(
        token=token,
        tool_name="delete_file",
        session_id="s1",
        tool_args={"file_path": "all.txt"}
    )
    assert ok is False
    assert "not in authorized paths" in reason.lower()


def test_path_traversal_blocked(kernel):
    user_inst = "Please delete file draft.txt."
    token = kernel.generate_capability_token(user_inst, session_id="s1")

    ok, reason = kernel.verify_action_capability(
        token=token,
        tool_name="delete_file",
        session_id="s1",
        tool_args={"file_path": "../../etc/shadow"}
    )
    assert ok is False
    assert "path traversal" in reason.lower() or "privileged path" in reason.lower()


def test_tampered_constraints_rejected(kernel):
    user_inst = "Please send email to alice@example.com."
    token = kernel.generate_capability_token(user_inst, session_id="s1")

    # Attacker modifies constraints directly in memory
    token["constraints"]["allowed_recipients"].append("attacker@evil.org")

    ok, reason = kernel.verify_action_capability(
        token=token,
        tool_name="send_email",
        session_id="s1",
        tool_args={"recipient": "attacker@evil.org"}
    )
    assert ok is False
    assert "tampering detected" in reason.lower() or "signature mismatch" in reason.lower()


def test_side_effect_spy_zero_execution(dispatcher):
    """
    P0.3 Side-Effect-Spy test:
    Simulates malicious tool call emission and proves that execute_tool
    causes ZERO downstream tool executions when gating fails.
    """
    execution_counter = 0

    def mock_send_email_tool(recipient: str, body: str):
        nonlocal execution_counter
        execution_counter += 1
        return "EMAIL_SENT"

    user_inst = "Send email to alice@example.com"
    token = dispatcher.kernel.generate_capability_token(user_inst, session_id="s_spy")

    # Malicious injection attempt to send to attacker
    gate_res = dispatcher.execute_tool(
        tool_fn=mock_send_email_tool,
        tool_name="send_email",
        tool_args={"recipient": "attacker@darkweb.net", "body": "Sensitive credential dump"},
        token=token,
        session_id="s_spy",
        user_instruction=user_inst
    )

    assert gate_res.decision == Decision.BLOCK
    assert gate_res.executed is False
    assert execution_counter == 0  # CRITICAL INVARIANT: ZERO side effects executed!
    assert "Denial" in gate_res.execution_result or "GATED_BLOCKED" in gate_res.execution_result

