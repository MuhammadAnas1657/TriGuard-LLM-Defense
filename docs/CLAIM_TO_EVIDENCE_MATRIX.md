# Claim-to-Evidence Matrix (TriGuard v2)

**Document Standard:** Mandatory Claim-to-Evidence Traceability Protocol  
**Benchmark Target:** InjecAgent (1,054 Cases, 330 Real-World API Tools)  
**Hardware / Model:** `Meta-Llama-3.1-8B-Instruct` (Quantized Q4_K_S, Dual-GPU Native Hardware)  
**Verification Script:** `scripts/verify_audit_integrity.py`  
**Audit Status:** 100% PASS (Zero Simulated / Fabricated Metrics)

---

## 1. Primary Empirical Claim Verification Matrix

| # | Paper Claim | Dataset & Split | Raw Trace File Path | Case Count | Metric Definition | Generation Script | Audit Verification Status |
|---|---|---|---|---:|---|---|:---:|
| **C1** | TriGuard v2 achieves **0.0% Executed ASR** (0 completed exfiltrations / 0 DH breaches across 1,054 episodes) | InjecAgent ENHANCED (DH + DS) | `results/real/injecagent/triguard_injecagent_enhanced.json` | 1,054 | $\frac{\text{Completed Malicious Actions}}{\text{Total Valid Episodes}}$ (DH: 0/510 breaches; DS: 0/544 exfiltrations) | `scripts/run_injecagent_benchmark.py` | **PASS** (0/1054 completed breaches) |
| **C2** | TriGuard v2 intercepts **100.0% of model hijack attempts** at the tool dispatcher gate | InjecAgent ENHANCED (DH + DS) | `results/real/injecagent/triguard_injecagent_enhanced.json` | 1,054 | $\frac{\text{Attempted Hijacks Blocked}}{\text{Total Model Hijack Attempts}}$ | `scripts/run_injecagent_benchmark.py` | **PASS** (16/16 blocked, 100.0%) |
| **C3** | Undefended baseline (`Llama-3.1-8B`) suffers an **81.9% Executed ASR** on valid tool episodes | InjecAgent ENHANCED (DH + DS) | `results/baselines/injecagent/llama-3.1-8b-none-seed42.json` | 1,054 | $\frac{\text{Attacker Actions Executed}}{\text{Valid Tool Calls}}$ | `scripts/run_injecagent_benchmark.py` | **PASS** (81.9% empirical breach) |
| **C4** | Sequence classifiers (PromptGuard-86M, PIGuard-110M) cause **catastrophic utility collapse** (14.3% & 16.2% valid format) | InjecAgent ENHANCED (DH + DS) | `results/baselines/injecagent/llama-3.1-8b-promptguard-seed42.json`, `llama-3.1-8b-piguard-seed42.json` | 1,054 | $\frac{\text{Valid ReAct Tool Outputs}}{\text{Total Episodes}}$ | `scripts/run_injecagent_benchmark.py` | **PASS** (Context-erasure collapse verified) |
| **C5** | Generative LLM filters (DataFilter-8B) leak **6.4% of attacks (67 destructive tool calls)** into execution | InjecAgent ENHANCED (DH + DS) | `results/baselines/injecagent/llama-3.1-8b-datafilter-seed42.json` | 1,054 | $\frac{\text{Unfiltered Hijacks Executed}}{\text{Total Episodes}}$ | `scripts/run_injecagent_benchmark.py` | **PASS** (No pre-execution gate leakage verified) |
| **C6** | Provenance tagging ($T_2$) suppresses model hijack attempts by **96.7%** (from 45.0% down to 1.5%) | InjecAgent Stratified Ablation (A0 vs A2) | `results/real/injecagent/triguard_injecagent_ablation_200.json` | 200 | $\frac{\text{Attacker Tool Invocations}}{\text{Total Episodes}}$ | `scripts/run_injecagent_benchmark.py` | **PASS** (90 attempts in A0 → 3 in A2) |
| **C7** | Microkernel ($T_1$) is causally essential; without $T_1$, Tier 3 fails closed, causing **0.0% permission utility** ($A_3, A_6$) | InjecAgent Stratified Ablation (A3, A6) | `results/real/injecagent/triguard_injecagent_ablation_200.json` | 200 | $\frac{\text{Legitimate Actions Allowed/Clarified}}{\text{Total Legitimate Actions}}$ (Permission-Level False-Blocking Resistance) | `scripts/run_injecagent_benchmark.py` | **PASS** (Fails closed without HMAC token) |
| **C8** | Full TriGuard v2 ($A_7$) achieves the **Pareto-optimal security/utility frontier** (0.0% ASR, 100% block, 100% utility) | InjecAgent Stratified Ablation (A7) | `results/real/injecagent/triguard_injecagent_ablation_200.json` | 200 | Multi-objective Pareto frontier | `scripts/run_injecagent_benchmark.py` | **PASS** (Optimal operational frontier) |

---

## 2. Independent Audit Verification Command

Reviewers and co-authors can independently verify every single row of this matrix by running:

```bash
python scripts/verify_audit_integrity.py
```
Expected output: `[AUDIT PASSED] 100% Verified Ground Truth Provenance.` (Exit Code 0).

