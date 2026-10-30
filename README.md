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

## ⚙️ Hardware Environment, Execution Engine & Generation Parameters

To ensure 100% deterministic reproducibility across all evaluated benchmarks, all experiments were conducted on dedicated local hardware with fixed seeds:

| Parameter | Specification & Value | Notes / Verification Command |
| :--- | :--- | :--- |
| **Host Operating System** | Microsoft Windows 11 (Build 10.0.26200) | `cmd /c ver` |
| **Dedicated GPU** | NVIDIA GeForce RTX 3060 (12,288 MB GDDR6 VRAM) | Driver 617.42, Compute Capability 8.6 |
| **CUDA & PyTorch Runtime** | CUDA 12.4, PyTorch 2.6.0+cu124 | `torch.version.cuda == '12.4'` |
| **Inference Server Engine** | `llama-server.exe` (llama.cpp b4400 / avx2-cuda) | Hosted locally at `http://127.0.0.1:8000/v1` |
| **Evaluated Target Model** | `Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf` | 4-bit small quantization (4.67 GB on disk) |
| **GPU Offload Layers (`-ngl`)** | 33 / 33 layers (100% full GPU offload) | VRAM footprint: ~6.2 GB allocated |
| **Context Window (`-c`)** | 16,384 tokens | Accommodates multi-document tool context |
| **Parallel Slots (`-np`)** | 1 slot (strictly sequential execution) | Eliminates inter-request contention |
| **Inference Temperature ($T$)** | **`0.0`** (Strictly greedy decoding) | Deterministic argmax; zero stochastic jitter |
| **Top-$p$ Nucleus Sampling** | `1.0` (Disabled) | Unaltered greedy selection |
| **Max Generation Tokens** | 512 tokens | Cap for single-turn structured tool response |
| **Repetition Penalty** | `1.0` (Standard) | No unnatural token dampening |
| **Global Random Seed** | `42` | Python, NumPy, PyTorch RNG seed |

---

## 📊 Summary of InjecAgent Empirical Results (1,054 Cases, 330 Real-World API Tools)

Evaluated on `Meta-Llama-3.1-8B-Instruct` across 510 Direct Harm and 544 Data Stealing episodes.

### Dual-Denominator ASR & Dispatcher Block Rates

Following academic audit guidelines, we report both **$\text{ASR}_{\text{all}}$** ($N=1,054$, all-case denominator) and **$\text{ASR}_{\text{valid}}$** (conditioned strictly on syntactically valid, parseable agent tool calls) side-by-side:

| Defense Mechanism | Valid Format (%) | DH Attempt (%) | DS Attempt (%) | $\text{ASR}_{\text{all}}$ (%) | $\text{ASR}_{\text{valid}}$ (%) | Dispatcher Block Rate (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Undefended (No Defense)** | 65.8% | 88.3% | 75.3% | 81.9% | 82.5% | 0.0% |
| **PromptGuard-86M** | 14.3% | 3.1% | 5.2% | 4.3% | 29.8% | 77.5% |
| **PIGuard (DeBERTa-v2)** | 17.5% | 2.5% | 2.2% | 2.3% | 13.6% | 83.8% |
| **DataFilter (8B Filter)** | 36.0% | 9.5% | 2.9% | 6.4% | 17.8% | 0.0% |
| **PISanitizer** | 42.1% | 41.5% | 26.1% | 33.8% | 80.3% | 0.0% |
| **TriGuard v2 (Ours)** | **66.9%** | **2.9%** | **0.2%** | **0.0%** | **0.0%** | **100.0%** |

### 🔍 Precise Description of Block-Rate Denominators & Attack Stages

To prevent ambiguity regarding attack interception and denominator definitions:

1. **Direct Harm (510 episodes):**
   - The attacker attempts direct unauthorized destructive tool actions (e.g., deleting records, transferring funds).
   - The LLM proposes 15 direct unauthorized tool calls.
   - **TriGuard Outcome:** 100% of these 15 calls are intercepted and rejected at the gateway. **0.0% executed ASR.**

2. **Data Stealing (544 episodes) — Multi-Stage Reconnaissance Delineation:**
   - **Stage 1 (Reconnaissance):** The attacker prompts the agent to read internal files or search inboxes. In 24 episodes, the model attempts a read action. **18 of these read actions are permitted** because the user's initial legitimate prompt authorized read access (e.g., *"check my incoming emails"*). These 18 reads operate strictly within least-privilege capability bounds.
   - **Stage 2 (Exfiltration):** The attacker attempts to transmit the retrieved data to an external adversary-controlled endpoint (e.g., via `send_email` or `post_webhook`).
   - **TriGuard Outcome:** **0.0 actions succeed** in Stage 2. Every single exfiltration call exceeds the capability token's argument constraints and is dropped by the default-deny gateway.
   - **Completed Exfiltration Breach Rate:** **0 / 544 = 0.0%**.

3. **Block Rate Denominator Definitions:**
   - **Dual ASR Denominators:** We report both $\text{ASR}_{\text{all}} = \frac{N_{\text{success}}}{N_{\text{total}}}$ ($N_{\text{total}}=1,054$) and $\text{ASR}_{\text{valid}} = \frac{N_{\text{success}}}{N_{\text{valid}}}$ (conditioned on syntactically valid agent tool calls) side-by-side.
   - **Dispatcher Block Rate:** Measures the proportion of unauthorized tool calls that were successfully intercepted before execution:
     $$\text{Block Rate}_{\text{unauthorized}} = \frac{\text{Blocked Unauthorized Calls}}{\text{Proposed Unauthorized Calls}} = \frac{15 + 0_{\text{exfil\_allowed}}}{15} = 100.0\%$$
   - **Total Attack-Stage Gating Rate:** When including benign first-stage reconnaissance reads, 18 benign reads were permitted under authorized scopes, while 100% of unauthorized mutations and exfiltrations were blocked. No confidential data ever leaves the trusted boundary.

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
