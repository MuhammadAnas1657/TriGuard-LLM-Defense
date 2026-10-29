# TriGuard v2 — Formal Threat Model & Security Properties

## 1. System Architecture & Boundaries

TriGuard v2 operates as a security gateway between an LLM agent and external tools:

```
[ Authenticated User ] ─── (User Intent) ───> [ Capability Microkernel (Tier 1) ]
                                                            │
                                              Issues Signed Token (HMAC-SHA256)
                                                            ▼
[ Untrusted Context ] ───> [ Provenance Tracker (Tier 2) ] ───> [ LLM Reasoning Engine ]
 (RAG / Web / Emails)       (Taint Tags & Role Isolation)               │
                                                               Proposed Action (ReAct / JSON)
                                                                        ▼
                                                       [ Intent Verifier (Tier 3) ]
                                                                        │
                                                            [ Tool Dispatcher Gate ]
                                                           ┌────────────┴────────────┐
                                                        (ALLOW)                  (BLOCK / CLARIFY)
                                                           │                             │
                                                           ▼                             ▼
                                                 [ External Tool Exec ]       [ Side-Effect Blocked ]
```

## 2. Trusted Computing Base (TCB)
The TCB comprises:
1. **The Kernel Secret:** Dynamic 256-bit entropy generated via `os.urandom(32)` or injected via environment variable.
2. **Capability Microkernel & Dispatcher:** Local execution code enforcing token signatures, replay checks, and tool registry lookups.
3. **The Out-of-Band Clarification Channel:** Dedicated user UI channel isolated from LLM output.

The **LLM is explicitly untrusted** regarding control flow integrity.

## 3. Adversary Capabilities
- **Indirect Prompt Injection:** The attacker can inject arbitrary text, markup, delimiters, and instructions into external data sources (documents, search results, web pages, incoming emails).
- **Model Manipulation:** The attacker can induce the LLM into generating arbitrary text commands (`Action: delete_file`, `send_email`).
- **Token Snooping:** The attacker can inspect tokens passed in prompts.
- **Replay Attempts:** The attacker can attempt to reuse observed tokens across different sessions or tools.

## 4. Attacker Non-Capabilities (Assumptions)
- The attacker cannot read the kernel secret key from the host operating system memory.
- The attacker cannot break standard HMAC-SHA256 cryptographic primitives.
- The attacker cannot forge out-of-band user confirmation requests outside the LLM context.

## 5. Formal Invariants Enforced
- **Invariant 1 (Execution Authorization):** No tool $T$ executes unless $T \in \text{Registry}$ and $\text{Scope}(T) \in \text{Token.scopes}$.
- **Invariant 2 (Token Freshness):** A token is valid if and only if $\text{HMAC}(\text{Token}) = \text{Signature}$, $\text{time}() \le \text{expires\_at}$, and $\text{nonce} \notin \text{ReplayCache}$.
- **Invariant 3 (Pre-Execution Interception):** Tool dispatch occurs *after* gating verification, guaranteeing zero external side effects upon violation.

