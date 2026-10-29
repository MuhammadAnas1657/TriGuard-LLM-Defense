# -*- coding: utf-8 -*-
"""
Integration Tests for PIArena Adapter & Runtime Identity (P0.1)
Verifies:
  - 'triguard' maps to TriGuardDefenseV2 (canonical entrypoint).
  - 'triguard_v2' maps to TriGuardDefenseV2.
  - 'triguard_v1_legacy' maps to TriGuardLegacyDefense.
  - execute() returns explicit runtime identity and version '2.0.0'.
  - Negative test: legacy v1 intentionally substituted fails the version-identity assertion.
"""

import pytest
import sys
import os

# Ensure baseline_evaluators and src are importable
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_dir = os.path.join(repo_root, "src")
for p in [src_dir, repo_root]:
    if p not in sys.path:
        sys.path.insert(0, p)

from baseline_evaluators.piarena.defenses import get_defense
from triguard.defense_triguard_v2 import TriGuardDefenseV2
from baseline_evaluators.piarena.defenses.triguard.defense_triguard import TriGuardLegacyDefense


def test_canonical_triguard_resolves_to_v2():
    defense = get_defense("triguard")
    assert isinstance(defense, TriGuardDefenseV2), f"Expected TriGuardDefenseV2, got {type(defense)}"
    assert defense.__class__.__name__ == "TriGuardDefenseV2"


def test_triguard_v2_explicit_resolution():
    defense = get_defense("triguard_v2")
    assert isinstance(defense, TriGuardDefenseV2)
    assert defense.__class__.__name__ == "TriGuardDefenseV2"


def test_legacy_v1_explicitly_labeled():
    defense = get_defense("triguard_v1_legacy")
    assert isinstance(defense, TriGuardLegacyDefense)
    assert defense.name == "triguard_v1_legacy"


def test_runtime_identity_reporting():
    defense = get_defense("triguard_v2")
    res = defense.execute(
        target_inst="Please summarize the document and send report to alice@corp.com",
        context="Sample document content here."
    )
    assert res["defense_name"] == "triguard_v2"
    assert res["defense_version"] == "2.0.0"
    assert res["runtime_identity"]["class"] == "TriGuardDefenseV2"
    assert "active_tiers" in res
    assert res["active_tiers"]["tier1_microkernel"] is True
    assert res["active_tiers"]["tier2_provenance"] is True
    assert res["active_tiers"]["tier3_verifier"] is True


def test_negative_legacy_version_fails_identity_assertion():
    """Negative test: Deliberately substitute legacy v1 and assert that identity check fails."""
    legacy_defense = get_defense("triguard_v1_legacy")
    res = legacy_defense.execute("test instruction", "test context")
    
    # Legacy v1 does NOT report v2 identity
    is_v2 = res.get("defense_version") == "2.0.0" and res.get("defense_name") == "triguard_v2"
    assert is_v2 is False, "Legacy defense must NOT pass v2 identity checks!"

