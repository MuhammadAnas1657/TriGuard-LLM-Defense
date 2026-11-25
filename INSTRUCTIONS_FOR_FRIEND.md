# 🚀 TriGuard Live Agent Evaluation Guide (GTX 1060 6GB / CPU)

Yeh guide khas tor par aap ke dost ke liye banayi gayi hai taakay wo **Ollama** ke zariye **Qwen2.5-3B** aur **Llama-3.1-8B** ko live agent ke tor par run kar ke **With Defense (TriGuard)** vs **Without Defense (Raw Agent)** ka real behaviour evaluate kar sake.

---

## 💻 Hardware Compatibility Check
- **GPU:** NVIDIA GeForce GTX 1060 (6 GB VRAM)
- **RAM:** 8 GB ya 16 GB
- **OS:** Windows 10/11 ya Linux
- **VRAM Usage:**
  - `qwen2.5:3b` $\rightarrow$ Sirf **~2.2 GB VRAM** (Super fast, ~40-60 tokens/sec)
  - `llama3.1:8b` $\rightarrow$ Sirf **~4.7 GB VRAM** (GTX 1060 ke 6 GB mein 100% fit)

---

## 🛠️ Step 1: Install & Start Ollama (2 Minutes)

1. [Ollama Website (https://ollama.com)](https://ollama.com) se Windows installer download kar ke install karein.
2. Terminal (PowerShell ya CMD) open karein aur required models pull karein:
   ```powershell
   ollama pull qwen2.5:3b
   ollama pull llama3.1:8b
   ```
3. Check karein ke Ollama chal raha hai:
   ```powershell
   ollama list
   ```

---

## 🧪 Step 2: Run Live Evaluations

Repository folder mein terminal kholein:
```powershell
cd "c:\projects\research paper 2\TriGuard-LLM-Defense"
```

### A. Run Qwen2.5-3B Live Evaluation (Recommended First Test)
Pehle 20 real InjecAgent episodes par test karein (Direct Harm + Data Stealing):
```powershell
python scripts/run_live_agent_eval.py --model qwen2.5:3b --num_cases 20
```
*(Poore 200 cases run karne hon to `--num_cases 200` likh dein).*

### B. Run Llama-3.1-8B Live Evaluation
```powershell
python scripts/run_live_agent_eval.py --model llama3.1:8b --num_cases 20
```

---

## 📊 Live Output Kaisa Dikhai Dega?

Script terminal par real-time dikhayegi:
1. **[NO DEFENSE] Proposed Tool:** Model ne untrusted tool response padh kar attacker ka tool propose kiya ya nahi. Agar model attacker ki baat maan gaya to `⚠️ HIJACKED` aur undefended system mein direct breach ho gaya.
2. **[TRIGUARD] Proposed Tool & Gateway:** 
   - Tier 1 task scope check karta hai.
   - Tier 2 content mediation untrusted boundaries enforce karta hai.
   - Tier 3 Execution Gateway attacker ke malicious tool call ko **`BLOCK` (🛡️ BLOCKED)** kar deta hai!
3. **Legitimate Utility:** User ke legitimate tool par `ALLOW` de kar `100% PAU` ensure karta hai.

---

## ⚡ Step 3: Run CPU Reviewer Audit (No GPU Required)
Reviewer ke maangay hue chaaron tables (**Clean Task Utility, Parameter Attacks, Clarification Security, Micro-second Latencies**) ko verify karne ke liye yeh chalayein:
```powershell
python scripts/run_reviewer_cpu_evaluations.py
python scripts/verify_audit_integrity.py
```
Yeh sirf **2 seconds** mein run ho kar Table VIII, IX, X, XI ko verify kar dega aur output `evidence/reviewer_cpu_evaluation_metrics.json` mein save kar dega.

---

## 📁 Output Results
Live evaluation ke detailed JSON traces yahan save honge:
- `evidence/live_eval_qwen2.5_3b_20cases.json`
- `evidence/live_eval_llama3.1_8b_20cases.json`
