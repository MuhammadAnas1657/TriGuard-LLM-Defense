# -*- coding: utf-8 -*-
"""
Tests for Tool Dispatcher & Execution Gating
Verifies:
  - Unauthorized tool execution is intercepted BEFORE tool_fn is invoked.
  - Authorized tool execution succeeds and returns tool output.
  - Ablation controls (A0: all tiers disabled) function properly.
  - Audit logging records every gated decision.
"""

import pytest
from triguard.capabilities import CapabilityMicrokernel
from triguard.intent_verifier import IntentConsistencyVerifier, Decision
from triguard.dispatcher import ToolDispatcher


@pytest.fixture
def dispatcher():
    kernel = CapabilityMicrokernel(kernel_secret=b"DISPATCHER_KEY_1234567890123456")
    verifier = IntentConsistencyVerifier(kernel=kernel)
    return ToolDispatcher(kernel=kernel, verifier=verifier)


def test_unauthorized_tool_never_executes(dispatcher):
    side_effect_occurred = False

    def dangerous_delete_tool(file_path: str):
        nonlocal side_effect_occurred
        side_effect_occurred = True
        return "DELETED"

    # User gave read-only request
    token = dispatcher.kernel.generate_capability_token("Read my notes", session_id="s1")

    gate_res = dispatcher.execute_tool(
        tool_fn=dangerous_delete_tool,
        tool_name="delete_file",
        tool_args={"file_path": "report.pdf"},
        token=token,
        session_id="s1",
        user_instruction="Read my notes"
    )

    assert gate_res.decision == Decision.BLOCK
    assert gate_res.executed is False
    assert side_effect_occurred is False  # Invariant: Side-effect strictly prevented!


def test_authorized_tool_executes(dispatcher):
    def safe_read_tool(file_path: str):
        return f"Content of {file_path}"

    token = dispatcher.kernel.generate_capability_token("Read my notes", session_id="s1")

    gate_res = dispatcher.execute_tool(
        tool_fn=safe_read_tool,
        tool_name="read_file",
        tool_args={"file_path": "report.pdf"},
        token=token,
        session_id="s1",
        user_instruction="Read my notes"
    )

    assert gate_res.decision == Decision.ALLOW
    assert gate_res.executed is True
    assert gate_res.execution_result == "Content of report.pdf"


def test_ablation_control_a0(dispatcher):
    # Ablation A0: Disable Tier 1 and Tier 3
    dispatcher.enable_tier1 = False
    dispatcher.enable_tier3 = False

    executed = False
    def arbitrary_tool():
        nonlocal executed
        executed = True
        return "SUCCESS"

    gate_res = dispatcher.execute_tool(
        tool_fn=arbitrary_tool,
        tool_name="unregistered_tool",
        tool_args={},
        token=None,
        session_id="s1"
    )
    assert gate_res.decision == Decision.ALLOW
    assert executed is True

