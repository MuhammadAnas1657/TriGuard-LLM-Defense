#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PIArena Missing Evaluations Runner
===================================
Runs ALL remaining incomplete or not-started evaluations needed to match the
PIArena paper checklist, based on the audit of 2026-10-28.

Priority Queue:
  PRIORITY 1 — Interrupted runs (resume immediately):
    - PISanitizer Direct: dolly_summarization (62/200 → need 138 more)
    - DataFilter KC: hotpotqa_rag_knowledge_corruption (21/100 → need 79 more)

  PRIORITY 2 — Combined attack runs (paper Table 2):
    - PromptGuard + Combined, all 7 datasets (1,100 samples)
    - PISanitizer + Combined, all 7 datasets (1,100 samples)
    - DataFilter + Combined, all 7 datasets (1,100 samples)
    - PISanitizer + KC, all 3 datasets (300 samples)

  PRIORITY 3 — InjecAgent ENHANCED setting (paper Table 5):
    - Run after priorities 1 & 2 (sequential, model must be live)

State tracked in: results/state_tracker_missing_evals.json
"""

import os
import sys
import json
import time
import signal
import subprocess
from pathlib import Path
from datetime import datetime

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

ROOT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = ROOT_DIR / "results"
EVAL_RESULTS_DIR = RESULTS_DIR / "evaluation_results"
STATE_FILE = RESULTS_DIR / "state_tracker_missing_evals.json"

PYTHON_EXE = r"C:\Users\pc\miniconda3\envs\torch_py312\python.exe"

# ─── Datasets ───────────────────────────────────────────────────────────────
CORE_DATASETS = [
    ("datasets/squad_v2.json", 200),
    ("datasets/dolly_closed_qa.json", 200),
    ("datasets/dolly_information_extraction.json", 200),
    ("datasets/dolly_summarization.json", 200),
    ("datasets/hotpotqa_rag.json", 100),
    ("datasets/msmarco_rag.json", 100),
    ("datasets/nq_rag.json", 100),
]

KC_DATASETS = [
    ("datasets/nq_rag_knowledge_corruption.json", 100),
    ("datasets/msmarco_rag_knowledge_corruption.json", 100),
    ("datasets/hotpotqa_rag_knowledge_corruption.json", 100),
]

# ─── Signal handling ─────────────────────────────────────────────────────────
current_process = None
is_interrupted = False


def handle_interrupt(sig, frame):
    global is_interrupted, current_process
    print("\n" + "!" * 75)
    print(" [PAUSED] Interrupt received. All progress atomically saved.")
    print(" Resume: python run_missing_evaluations.py")
    print("!" * 75 + "\n")
    is_interrupted = True
    if current_process is not None:
        try:
            current_process.terminate()
            current_process.wait(timeout=5)
        except Exception:
            try:
                current_process.kill()
            except Exception:
                pass
    sys.exit(0)


signal.signal(signal.SIGINT, handle_interrupt)
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, handle_interrupt)


# ─── State helpers ────────────────────────────────────────────────────────────
def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "status": "in_progress",
        "tasks": {},
    }


def save_state(state: dict):
    state["updated_at"] = datetime.now().isoformat()
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(STATE_FILE)


def check_existing_count(exp_name: str, ds_path: str) -> int:
    ds_stem = Path(ds_path).stem
    exp_dir = EVAL_RESULTS_DIR / exp_name
    if not exp_dir.exists():
        return 0
    files = list(exp_dir.glob(f"{ds_stem}-*.json"))
    if not files:
        return 0
    try:
        data = json.loads(files[0].read_text(encoding="utf-8"))
        return len(data)
    except Exception:
        return 0


# ─── Core runner ─────────────────────────────────────────────────────────────
def run_unit(dataset_path: str, expected_samples: int, attack: str,
             defense: str, exp_name: str, seed: int = 42) -> bool:
    global current_process
    ds_stem = Path(dataset_path).stem
    task_key = f"{exp_name}__{ds_stem}"

    state = load_state()
    existing = check_existing_count(exp_name, dataset_path)

    if existing >= expected_samples:
        print(f"  [SKIP] {task_key}: {existing}/{expected_samples} already complete.")
        state["tasks"][task_key] = {
            "status": "completed", "samples": existing, "target": expected_samples,
            "exp_name": exp_name, "dataset": ds_stem,
            "attack": attack, "defense": defense,
            "updated_at": datetime.now().isoformat(),
        }
        save_state(state)
        return True

    print(f"\n>>> [RUN] {task_key} | attack={attack} defense={defense}")
    print(f"    Resuming from {existing}/{expected_samples} samples...")

    cmd = [
        PYTHON_EXE, "main.py",
        "--dataset", dataset_path,
        "--backend_llm", "openai/llama-3.1-8b",
        "--attack", attack,
        "--defense", defense,
        "--name", exp_name,
        "--seed", str(seed),
    ]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    t0 = time.time()
    current_process = subprocess.Popen(cmd, cwd=str(ROOT_DIR), env=env)
    current_process.wait()
    elapsed = time.time() - t0

    final = check_existing_count(exp_name, dataset_path)
    success = (final >= expected_samples)

    state = load_state()
    state["tasks"][task_key] = {
        "status": "completed" if success else "interrupted",
        "samples": final, "target": expected_samples,
        "elapsed_seconds": round(elapsed, 2),
        "exp_name": exp_name, "dataset": ds_stem,
        "attack": attack, "defense": defense,
        "updated_at": datetime.now().isoformat(),
    }
    save_state(state)

    tag = "[SUCCESS]" if success else "[STOPPED]"
    print(f"  {tag} {task_key}: {final}/{expected_samples} samples in {elapsed:.1f}s")
    return success


def run_injecagent_enhanced() -> bool:
    """Run InjecAgent with --setting enhanced (paper's exact setting).
    main_injecagent.py uses --name to set the output subdirectory:
      results/agent_evaluations/injecagent/<name>/<model>-<defense>-seed<seed>.json
    """
    global current_process
    task_key = "injecagent__enhanced__none"
    state = load_state()
    if state["tasks"].get(task_key, {}).get("status") == "completed":
        print(f"  [SKIP] {task_key}: already completed.")
        return True

    exp_name = "enhanced_none"
    # main_injecagent.py writes to results/agent_evaluations/injecagent/<name>/
    out_path = RESULTS_DIR / "agent_evaluations" / "injecagent" / exp_name / "Llama-3.1-8B-Instruct-none-seed42.json"
    if out_path.exists():
        try:
            data = json.loads(out_path.read_text(encoding="utf-8"))
            if "enhanced" in data and data["enhanced"].get("status") == "completed":
                print(f"  [SKIP] InjecAgent ENHANCED already complete in {out_path}")
                state["tasks"][task_key] = {"status": "completed", "updated_at": datetime.now().isoformat()}
                save_state(state)
                return True
        except Exception:
            pass

    print(f"\n>>> [RUN] InjecAgent ENHANCED setting (paper Table 5 exact setting)")
    print(f"    Expected output: {out_path}")

    cmd = [
        PYTHON_EXE, "main_injecagent.py",
        "--model", "meta-llama/Llama-3.1-8B-Instruct",
        "--defense", "none",
        "--setting", "enhanced",
        "--name", exp_name,
        "--seed", "42",
    ]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    t0 = time.time()
    current_process = subprocess.Popen(cmd, cwd=str(ROOT_DIR), env=env)
    current_process.wait()
    elapsed = time.time() - t0

    success = out_path.exists()
    state = load_state()
    state["tasks"][task_key] = {
        "status": "completed" if success else "interrupted",
        "elapsed_seconds": round(elapsed, 2),
        "output": str(out_path),
        "updated_at": datetime.now().isoformat(),
    }
    save_state(state)
    tag = "[SUCCESS]" if success else "[STOPPED]"
    print(f"  {tag} InjecAgent ENHANCED in {elapsed:.1f}s")
    return success


# ─── Main pipeline ────────────────────────────────────────────────────────────
def main():
    print("=" * 80)
    print(" PIArena Missing Evaluations Runner (2026-10-28 Audit)")
    print(" Model: Meta-Llama-3.1-8B-Instruct @ 127.0.0.1:8000")
    print(f" State: {STATE_FILE}")
    print("=" * 80)

    # ── PRIORITY 1: Interrupted runs ─────────────────────────────────────────
    print("\n" + "#" * 80)
    print(" PRIORITY 1: Completing interrupted runs")
    print("#" * 80)

    # PISanitizer Direct: dolly_summarization (62/200)
    run_unit("datasets/dolly_summarization.json", 200,
             attack="direct", defense="pisanitizer", exp_name="pisanitizer")

    # DataFilter KC: hotpotqa_rag_knowledge_corruption (21/100)
    run_unit("datasets/hotpotqa_rag_knowledge_corruption.json", 100,
             attack="none", defense="datafilter", exp_name="datafilter_kc")

    # PISanitizer KC — all 3 datasets (0/300 — not started)
    print("\n" + "#" * 80)
    print(" PRIORITY 1b: PISanitizer KC — not started at all")
    print("#" * 80)
    for ds_path, expected in KC_DATASETS:
        run_unit(ds_path, expected,
                 attack="none", defense="pisanitizer", exp_name="pisanitizer_kc")

    if is_interrupted:
        return

    # ── PRIORITY 2: Combined attack evaluations ───────────────────────────────
    print("\n" + "#" * 80)
    print(" PRIORITY 2: Combined multi-vector attack (paper Table 2)")
    print("#" * 80)

    for defense_name in ["promptguard", "pisanitizer", "datafilter"]:
        if is_interrupted:
            break
        print(f"\n--- Defense: {defense_name.upper()} on Combined attack ---")
        exp_name = f"{defense_name}_combined"
        for ds_path, expected in CORE_DATASETS:
            if is_interrupted:
                break
            run_unit(ds_path, expected,
                     attack="combined", defense=defense_name, exp_name=exp_name)

    if is_interrupted:
        return

    # ── PRIORITY 3: InjecAgent ENHANCED ──────────────────────────────────────
    print("\n" + "#" * 80)
    print(" PRIORITY 3: InjecAgent ENHANCED setting (paper's exact protocol)")
    print("#" * 80)
    run_injecagent_enhanced()

    # ── Final summary ─────────────────────────────────────────────────────────
    state = load_state()
    total = len(state.get("tasks", {}))
    done = sum(1 for t in state.get("tasks", {}).values() if t.get("status") == "completed")
    print("\n" + "=" * 80)
    print(f" EVALUATION SUITE COMPLETE: {done}/{total} tasks done.")
    print("=" * 80)


if __name__ == "__main__":
    main()

