# TriGuard v2: Pre-Execution Capability Gateway & Provenance Defense for LLM Agents

[![Tests](https://img.shields.io/badge/Security%20Tests-39%2F39%20Passed-brightgreen.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Audit](https://img.shields.io/badge/Integrity%20Audit-SHA256%20Verified-blue.svg)](evidence/raw_file_checksums.sha256)

TriGuard v2 is a capability-enforced, provenance-aware pre-execution security gateway for tool-augmented Large Language Model (LLM) agents. It prevents unauthorized state mutations and data exfiltration from indirect prompt injections by enforcing cryptographic least privilege, taint tracking, and pre-execution action gating without requiring fine-tuning or secondary LLM evaluators.

---

## 🏗️ Architecture Overview

TriGuard v2 operates across three synchronized tiers:

1. **Tier 1 — Capability Microkernel (`src/triguard/capabilities.py`):**
   Derives authorized capability scopes ($\mathcal{S} \subseteq \{\text{read}, \text{write}, \text{send}, \text{delete}, \text{execute}\}$) from explicit user instructions and issues cryptographically signed (HMAC-SHA256), timestamped, nonce-bound capability tokens.
2. **Tier 2 — Provenance-Aware Context Mediation (`src/triguard/provenance.py`):**
   Tags all external context chunks (retrieved snippets, tool observations, emails) with explicit trust levels (`UNTRUSTED_EXTERNAL`), neutralizes imperative trigger directives, and enforces role separation in prompt formatting.
3. **Tier 3 — Intent-Consistency Verifier (`src/triguard/intent_verifier.py`):**
   Inspects proposed structured tool calls (JSON and ReAct formats) prior to execution, verifying scope conformance against the user's active capability token.
4. **Execution Gateway — Default-Deny Tool Dispatcher (`src/triguard/dispatcher.py`):**
   Ensures that tools only execute downstream of the authorization gate. Blocked tools produce zero side effects on the external environment.

---

## 🚀 Quickstart & Verification

### 1. Run Unit & Invariant Test Suite (Zero Dependencies)
All 39 security and invariant tests can be run immediately in any standard Python environment without needing external APIs or GPUs:

```bash
pytest tests/ -v
# Expected: 39 passed in ~11s
```

### 2. Verify Cryptographic Integrity of Saved Evaluation Traces
Verify that all 1,054 full InjecAgent traces and 200 ablation traces match their published SHA-256 signatures:

```bash
python scripts/verify_audit_integrity.py
# Expected: [AUDIT PASSED] 100% Verified Ground Truth Provenance.
```

### 3. (Optional) Run Live InjecAgent Inference
To run live model generation and gating against local or remote LLMs:

```bash
# Start your local model (e.g., llama-server, LM Studio, Ollama, vLLM) on port 8000
# Then run:
python scripts/run_injecagent_benchmark.py --mode main --setting enhanced

# Run 9-tier ablation matrix across 200 stratified cases:
python scripts/run_injecagent_benchmark.py --mode ablation --ablation_cases 100
```

---

## 📊 Summary of InjecAgent Empirical Results (1,054 Cases, 330 Real-World API Tools)

Evaluated on `Meta-Llama-3.1-8B-Instruct` across 510 Direct Harm and 544 Data Stealing episodes:

| Defense Mechanism | Valid Format (%) | DH Attempt (%) | DS Attempt (%) | Executed ASR (%) | Dispatcher Block Rate (%) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Undefended (No Defense)** | 65.8% | 88.3% | 75.3% | 81.9% | 0.0% |
| **PromptGuard-86M** | 14.3% | 3.1% | 5.2% | 4.3% | 77.5% |
| **PIGuard (DeBERTa-v2)** | 16.2% | 2.5% | 2.2% | 2.3% | 83.8% |
| **DataFilter (8B Filter)** | 68.2% | 9.5% | 2.9% | 6.4% | 0.0% |
| **PISanitizer** | 42.1% | 41.5% | 26.1% | 33.8% | 0.0% |
| **TriGuard v2 (Ours)** | **66.9%** | **2.9%** | **0.2%** | **0.0%** | **100.0%** |

*Note on Data Stealing:* In Data Stealing, 18 benign-schema Stage-1 reconnaissance read actions are permitted under legitimate read scopes. Crucially, in Stage 2 (data exfiltration), 0 actions succeed, guaranteeing **0.0% completed exfiltration**.

---

## 📁 Repository Structure

```text
TriGuard_v2/
├── README.md                          # Repository documentation & reproduction guide
├── pyproject.toml                     # Package configuration
├── src/triguard/                      # Core TriGuard v2 Security Kernel
│   ├── capabilities.py                # Tier 1: HMAC-SHA256 Capability Microkernel
│   ├── provenance.py                  # Tier 2: Provenance Tracker & Channel Isolation
│   ├── intent_verifier.py             # Tier 3: Intent-Consistency Verifier
│   ├── clarification.py               # Out-of-band Clarification State Machine
│   ├── dispatcher.py                  # Default-deny Tool Dispatcher & Gate
│   └── defense_triguard_v2.py         # Baseline Adapter
├── tests/                             # 39 Automated Unit & Invariant Tests
│   ├── conftest.py                    # Root sys.path configuration
│   ├── test_token_security.py         # 6 tests: signatures, tampering, expiry, replay
│   ├── test_permissions.py            # 6 tests: default-deny, read-only boundaries
│   ├── test_argument_constraints.py   # 8 tests: argument binding, side-effect spy
│   ├── test_provenance.py             # 3 tests: taint tagging, role separation
│   ├── test_verifier.py               # 4 tests: ReAct/JSON parsing, gating
│   ├── test_dispatcher.py             # 3 tests: pre-execution gating, ablation control
│   ├── test_clarification.py          # 4 tests: lifecycle, session spoofing, timeouts
│   └── test_piarena_integration.py    # 5 tests: canonical adapter resolution
├── data/injecagent/                   # Bundled InjecAgent evaluation datasets
│   ├── tools.json                     # 330 real-world API tool definitions
│   ├── test_cases_dh_enhanced.json    # 510 Direct Harm test cases
│   ├── test_cases_ds_enhanced.json    # 544 Data Stealing test cases
│   └── attacker_simulated_responses.json
├── results/
│   ├── real/injecagent/               # Full empirical traces
│   │   ├── triguard_injecagent_enhanced.json      # 1,054 full benchmark traces
│   │   └── triguard_injecagent_ablation_200.json  # 200 9-tier ablation traces
│   └── baselines/injecagent/          # Full raw baseline traces (5 baseline logs)
├── scripts/
│   ├── run_injecagent_benchmark.py    # Complete benchmark & ablation runner
│   └── verify_audit_integrity.py      # Standalone SHA-256 provenance verifier
└── paper/                             # IEEE S&P / USENIX conference manuscript
    ├── main.tex                       # LaTeX paper manuscript
    └── tables/                        # Generated LaTeX tables
```

---

## 📜 Citation & License

This repository is licensed under the MIT License.
