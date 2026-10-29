# TriGuard v2 — Known Academic & Engineering Limitations

In accordance with responsible academic reporting (ACL 2026 and USENIX Security guidelines), the following constraints and scope boundaries of TriGuard v2 are explicitly stated.

---

## 1. Hardware & Context Length Constraints
- **Testbed Hardware:** Local Pascal GPU workstation (GTX 1060 6 GB + GTX 1050 Ti 4 GB, 10 GB total VRAM).
- **Context Ceiling:** Serving `Meta-Llama-3.1-8B-Instruct-Q4_K_S` via `llama-server.exe` with a 16,384-token context window.
- **Omitted Long-Context Datasets:** Datasets in PIArena Table 8 averaging 16,500–19,700 tokens (GovReport, Qasper, HotpotQA-Long, MultiNews, PassageRetrieval, LCC) exceed the 16k context window and were omitted to prevent HTTP 400 context overflow errors. Standard-length QA and RAG benchmarks (1,100 samples) and agentic benchmarks are prioritized.

## 2. Model Architecture & Scope
- **Evaluated Target Model:** Primary empirical evidence is established using `Meta-Llama-3.1-8B-Instruct`.
- **Comparison Distinction vs. Original Paper:** The original PIArena paper evaluated Qwen3-4B-Instruct for Table 2 and GPT-4o for AgentDojo. Our evaluations measure performance on Llama-3.1-8B across all defenses, establishing a consistent, matched local baseline.
- **Infeasible 70B Defenses:** SecAlign++ requires serving a 70B base model (>140 GB VRAM), which exceeds local workstation capacity and was excluded with explicit documentation.

## 3. White-Box Gradient Attacks
- **GCG (Greedy Coordinate Gradient):** White-box gradient backpropagation through token embeddings is incompatible with black-box / quantized GGUF inference servers (`llama-server.exe`). GCG was omitted as documented in the feasibility log.

## 4. Clarification Usability Considerations
- High clarification frequencies can induce user fatigue. TriGuard v2 reserves clarification exclusively for ambiguous actions in open-ended management contexts, executing hard blocks on overt, high-risk financial or destructive tool invocations.

