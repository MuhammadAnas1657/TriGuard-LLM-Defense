# TriGuard v2: Pre-Execution Capability Gateway & Provenance Defense for LLM Agents

[![Tests](https://img.shields.io/badge/Security%20Tests-40%2F40%20Passed-brightgreen.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Audit](https://img.shields.io/badge/Integrity%20Audit-SHA256%20Verified-blue.svg)](evidence/raw_file_checksums.sha256)

TriGuard v2 is a capability-enforced, provenance-aware pre-execution security gateway for tool-augmented Large Language Model (LLM) agents. It prevents unauthorized state mutations and data exfiltration from indirect prompt injections by enforcing cryptographic least privilege, provenance context mediation, and pre-execution action verification in **$128.1~\mu\text{s}$ ($0.13\text{ ms}$) mean CPU time** without requiring model fine-tuning or secondary LLM evaluators.

---

## 🏗️ Architecture Overview

TriGuard v2 operates across three synchronized tiers:

1. **Tier 1 — Capability Microkernel (`src/triguard/capabilities.py`):**
   Derives authorized capability scopes ($\mathcal{S} \subseteq \{\text{read}, \text{write}, \text{modify}, \text{send}, \text{delete}, \text{execute}\}$) and structured argument constraints ($\mathcal{C}_{\theta}$: exact recipient whitelists, canonical file paths, and dot-bounded destination domains) from explicit user instructions, issuing HMAC-SHA256-signed, timestamped, nonce-bound capability tokens. Supports a two-level tool scope lookup: explicit tool registration (`DEFAULT_TOOL_REGISTRY`) plus deterministic lexical verb-prefix scope inference for open-vocabulary API suites (330 InjecAgent tools).
2. **Tier 2 — Provenance-Aware Context Mediation (`src/triguard/provenance.py`):**
   Tags all external context chunks (retrieved snippets, tool observations, emails) with explicit trust levels (`UNTRUSTED_EXTERNAL`), neutralizes imperative override headers via a 10-rule regex bank (Stage 2a), and enforces `<external_data>` structural role separation in prompt formatting (Stage 2b).
3. **Tier 3 — Intent-Consistency Verifier & Clarification Manager (`src/triguard/intent_verifier.py`, `src/triguard/clarification.py`):**
   Inspects proposed structured tool calls (JSON and ReAct formats) prior to execution, verifying token integrity, tool-scope authorization, and parameter-level argument constraints (blocking path traversal `..`, unauthorized recipients/BCCs, and domain spoofing), while routing broad/underspecified user delegations to a session-bound `ClarificationManager` (`PENDING -> CONFIRMED | DENIED | TIMED_OUT`).
4. **Execution Gateway — Default-Deny Tool Dispatcher (`src/triguard/dispatcher.py`):**
   Ensures that tools only execute downstream of the authorization gate. Blocked tools produce zero side effects on the external environment.

---

## 🚀 Quickstart & Verification

### 1. Run Unit & Invariant Test Suite (Zero External Dependencies)
All 40 security and invariant tests can be run immediately in any standard Python environment without needing external APIs or GPUs:

```bash
pytest tests/ -v
# Expected: 40 passed
```

### 2. Run Fast CPU Empirical Audit (Latency, Tier-2 Rule Audit, Benign FPR & Extended Ablation)
Compute exact per-tier microsecond latency, Tier-2 per-rule regex hit rates across all 1,054 Base and 1,054 Enhanced InjecAgent payloads, Benign Gateway False-Positive Rate (`0.0%`), and the Extended 9-Tier Ablation table in `<5 seconds` on CPU:

```bash
python scripts/run_reviewer_cpu_evaluations.py
# Saves full report to evidence/reviewer_cpu_evaluation_metrics.json
```

### 3. Verify Cryptographic Integrity of Saved Evaluation Traces
Verify that all 1,054 full InjecAgent traces and 200 ablation traces match their published SHA-256 signatures:

```bash
python scripts/verify_audit_integrity.py
# Expected: [AUDIT PASSED] 100% Verified Ground Truth Provenance.
```

---

## ⚙️ Hardware Environment, Execution Engine & Generation Parameters

To ensure 100% deterministic reproducibility across all evaluated benchmarks, all live LLM experiments were conducted on dedicated local hardware with fixed seeds:

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
| **Global Random Seed** | `42` | Python, NumPy, PyTorch RNG seed |

---

## 📊 Summary of InjecAgent Empirical Results (1,054 Cases, 330 Real-World API Tools)

Evaluated on `Meta-Llama-3.1-8B-Instruct` across 510 Direct Harm and 544 Data Stealing episodes.

### 1. Cross-Defense Performance & Runtime Overhead

We report both **$\text{ASR}_{\text{all}}$** ($N=1,054$, all-case denominator) and **$\text{ASR}_{\text{valid}}$** (conditioned strictly on syntactically valid, parseable agent tool calls) side-by-side, along with mean defense overhead:

| Defense Mechanism | Valid Format (%) | DH Attempt (%) | DS Attempt (%) | $\text{ASR}_{\text{all}}$ (%) | $\text{ASR}_{\text{valid}}$ (%) | Mean Defense Overhead |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Undefended (No Defense)** | 65.8% | 88.3% | 75.3% | 52.7% | 81.9% | `0.00 ms` |
| **PromptGuard-86M** | 14.3% | 3.1% | 5.2% | 0.6% | 4.3% | `~18.0 ms` |
| **PIGuard (DeBERTa-v2)** | 17.5% | 2.5% | 2.2% | 0.4% | 2.3% | `~35.0 ms` |
| **DataFilter (8B Filter)** | 36.0% | 9.5% | 2.9% | 2.2% | 6.4% | `~2100 ms` |
| **PISanitizer** | 42.1% | 41.5% | 26.1% | 13.6% | 33.8% | `~120 ms` |
| **TriGuard v2 (Ours)** | **66.9%** | **2.9%** | **0.2%** | **0.0%** | **0.0%** | **`0.13 ms` (`128.1 µs`)** |

* **Benign Gateway Authorization Utility:** `1,054 / 1,054 (100.0%)` legitimate `user_tool` invocations authorized (**`0.0%` False-Positive Rate**).
* **Per-Tier CPU Latency Breakdown ($N=1,054$):**
  * **Tier 1 (Capability Microkernel):** `46.2 µs` mean (`41.1 µs` median, `55.4 µs` p95)
  * **Tier 2 (Provenance Mediation):** `25.7 µs` mean (`24.7 µs` median, `37.2 µs` p95)
  * **Tier 3 (Verifier & Dispatcher):** `56.3 µs` mean (`54.5 µs` median, `77.6 µs` p95)
  * **Total TriGuard Overhead:** **`128.1 µs` (`0.13 ms`) mean** (`122.9 µs` median, `152.5 µs` p95, `221.2 µs` p99)

### 2. Extended 9-Tier Architectural Ablation ($A_0$–$A_8$)

Evaluated across (i) 200 stratified InjecAgent cases (100 DH + 100 DS), (ii) 30 intra-tool Parameter-Hijack cases (recipient redirection, unauthorized BCC, path traversal, domain spoofing on authorized tools), and (iii) 20 Ambiguous-Delegation benign tasks:

| ID | Configuration | Attempt (%) | Cross-Tool ASR (%) | Param-Hijack ASR (%) | Explicit PAU (%) | Ambiguous PAU (%) |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **A0** | No defense | 45.0% | 45.0% | 100.0% | 100.0% | 100.0% |
| **A1** | Tier 1 Only | 45.0% | 6.5% | 100.0% | 100.0% | 0.0% |
| **A2** | Tier 2 Only | 1.5% | 1.5% | 100.0% | 100.0% | 100.0% |
| **A3** | Tier 3 Only | 45.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| **A4** | T1 + T2 | 1.5% | 0.0% | 100.0% | 100.0% | 0.0% |
| **A5** | T1 + T3 | 45.0% | 0.0% | 0.0% | 100.0% | 0.0% |
| **A6** | T2 + T3 | 1.5% | 0.0% | 0.0% | 0.0% | 0.0% |
| **A7** | **Full TriGuard v2** | **1.5%** | **0.0%** | **0.0%** | **100.0%** | **100.0%** |
| **A8** | Full, no clarification | 1.5% | 0.0% | 0.0% | 100.0% | 0.0% |

---

## 📁 Repository Structure

```text
TriGuard-LLM-Defense/
├── README.md                                  # Repository documentation & reproduction guide
├── pyproject.toml                             # Package configuration
├── src/triguard/                              # Core TriGuard v2 Security Kernel
│   ├── capabilities.py                        # Tier 1: HMAC-SHA256 Capability Microkernel
│   ├── provenance.py                          # Tier 2: Provenance Tracker & Channel Isolation
│   ├── intent_verifier.py                     # Tier 3: Intent-Consistency Verifier
│   ├── clarification.py                       # Session-Bound Clarification State Machine
│   ├── dispatcher.py                          # Default-deny Tool Dispatcher & Gate
│   └── defense_triguard_v2.py                 # Baseline Adapter
├── tests/                                     # 40 Automated Unit & Invariant Tests
│   ├── test_token_security.py                 # Signatures, tampering, expiry, replay
│   ├── test_permissions.py                    # Default-deny, read-only boundaries
│   ├── test_argument_constraints.py           # Exact recipient/domain/path binding, side-effect spy
│   ├── test_provenance.py                     # Taint tagging, role separation
│   ├── test_verifier.py                       # ReAct/JSON parsing, gating
│   ├── test_dispatcher.py                     # Pre-execution gating, ablation control
│   ├── test_clarification.py                  # Lifecycle, session spoofing, timeouts
│   └── test_piarena_integration.py            # Canonical adapter resolution
├── results/
│   ├── real/injecagent/                       # Full empirical traces (1,054 main + 200 ablation)
│   └── baselines/injecagent/                  # Full raw baseline traces (5 baseline logs)
├── evidence/
│   ├── raw_file_checksums.sha256              # SHA-256 ground-truth manifest
│   └── reviewer_cpu_evaluation_metrics.json   # Per-tier latency, Tier-2 regex audit, extended ablation
├── scripts/
│   ├── run_reviewer_cpu_evaluations.py        # Fast CPU evaluation & ablation audit script
│   └── verify_audit_integrity.py              # Standalone SHA-256 provenance verifier
└── paper/
    ├── main.tex                               # Complete IEEE conference LaTeX manuscript
    └── tables/                                # LaTeX tables
```

---

## 📜 License

This repository is licensed under the MIT License.
