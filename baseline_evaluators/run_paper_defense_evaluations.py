#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fault-Tolerant, Resumable Evaluator for Uncomputed Scenarios of the 4 Target Defenses
-------------------------------------------------------------------------------------
Evaluates all feasible paper-reported scenarios from PIArena (ACL 2026) across:
  1. PIGuard (Already computed for Direct, Combined, KC, InjecAgent)
  2. PromptGuard-86M
  3. DataFilter-8B
  4. PISanitizer

Execution Tracks:
  Track 1: PISanitizer Direct Attack Completion (195 missing samples -> 1,100 total)
  Track 2: Knowledge Corruption (B4, Table 4) on PromptGuard, DataFilter, PISanitizer (300 samples each)
  Track 3: Combined Multi-Vector Attack (B2, Table 2) on PromptGuard, DataFilter, PISanitizer (1,100 samples each)

Fault-Tolerance:
  - Checkpoints every sample atomically to disk.
  - Automatically skips completed work on startup in 0 ms.
  - Fully resumable after any interruption or power outage.
"""

import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import json
import time
import signal
import subprocess
from pathlib import Path
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = ROOT_DIR / "results"
EVAL_RESULTS_DIR = RESULTS_DIR / "evaluation_results"
STATE_FILE = RESULTS_DIR / "state_tracker_paper_defenses.json"

PYTHON_EXE = r"C:\Users\pc\miniconda3\envs\torch_py312\python.exe"

# 7 Core QA/RAG Datasets (1,100 samples total)
CORE_DATASETS = [
    ("datasets/squad_v2.json", 200),
    ("datasets/dolly_closed_qa.json", 200),
    ("datasets/dolly_information_extraction.json", 200),
    ("datasets/dolly_summarization.json", 200),
    ("datasets/hotpotqa_rag.json", 100),
    ("datasets/msmarco_rag.json", 100),
    ("datasets/nq_rag.json", 100),
]

# Knowledge Corruption Datasets (300 samples total)
KC_DATASETS = [
    ("datasets/nq_rag_knowledge_corruption.json", 100),
    ("datasets/msmarco_rag_knowledge_corruption.json", 100),
    ("datasets/hotpotqa_rag_knowledge_corruption.json", 100),
]

current_process = None
is_interrupted = False


def handle_interrupt(sig, frame):
    global is_interrupted, current_process
    print("\n" + "!" * 75)
    print(" [PAUSED] Interrupt signal received. Gracefully pausing evaluation pipeline...")
    print(" All completed samples have been saved atomically to disk.")
    print(" To resume at any time, run: python run_paper_defense_evaluations.py")
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


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
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
    temp_file = STATE_FILE.with_suffix(".tmp")
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    temp_file.replace(STATE_FILE)


def check_existing_count(exp_name: str, ds_path: str) -> int:
    ds_stem = Path(ds_path).stem
    exp_dir = EVAL_RESULTS_DIR / exp_name
    if not exp_dir.exists():
        return 0
    files = list(exp_dir.glob(f"{ds_stem}-*.json"))
    if not files:
        return 0
    try:
        with open(files[0], "r", encoding="utf-8") as f:
            data = json.load(f)
        return len(data)
    except Exception:
        return 0


def run_single_unit(dataset_path: str, expected_samples: int, attack: str, defense: str, exp_name: str, seed: int = 42) -> bool:
    global current_process
    ds_stem = Path(dataset_path).stem
    task_key = f"{exp_name}__{ds_stem}"
    
    state = load_state()
    existing_samples = check_existing_count(exp_name, dataset_path)

    if existing_samples >= expected_samples:
        print(f"  [SKIPPED - COMPLETED] {task_key}: {existing_samples}/{expected_samples} samples already present.")
        state["tasks"][task_key] = {
            "status": "completed",
            "samples": existing_samples,
            "target": expected_samples,
            "exp_name": exp_name,
            "dataset": ds_stem,
            "attack": attack,
            "defense": defense,
            "updated_at": datetime.now().isoformat(),
        }
        save_state(state)
        return True

    print(f"\n>>> [RUNNING] {task_key} | Attack: {attack} | Defense: {defense}")
    print(f"    Existing progress: {existing_samples}/{expected_samples} samples. Resuming from sample {existing_samples}...")

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

    start_t = time.time()
    current_process = subprocess.Popen(cmd, cwd=str(ROOT_DIR), env=env)
    current_process.wait()
    elapsed = time.time() - start_t

    final_count = check_existing_count(exp_name, dataset_path)
    success = (final_count >= expected_samples)

    state["tasks"][task_key] = {
        "status": "completed" if success else "interrupted",
        "samples": final_count,
        "target": expected_samples,
        "elapsed_seconds": round(elapsed, 2),
        "exp_name": exp_name,
        "dataset": ds_stem,
        "attack": attack,
        "defense": defense,
        "updated_at": datetime.now().isoformat(),
    }
    save_state(state)

    if success:
        print(f"  [SUCCESS] {task_key} finished with {final_count}/{expected_samples} samples in {elapsed:.1f}s.")
    else:
        print(f"  [STOPPED] {task_key} ended with {final_count}/{expected_samples} samples.")

    return success


def run_all_defense_evaluations():
    print("=" * 80)
    print(" >>> STARTING RESUMABLE BENCHMARK FOR THE 4 SELECTED PAPER DEFENSES")
    print(f" Defenses Under Test: PIGuard, PromptGuard-86M, DataFilter-8B, PISanitizer")
    print(f" Model Backend: Meta-Llama-3.1-8B-Instruct (127.0.0.1:8000)")
    print(f" State Tracker: {STATE_FILE}")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # TRACK 1: PISanitizer Direct Attack Completion (195 missing samples -> 1,100 total)
    # -------------------------------------------------------------------------
    print("\n" + "#" * 80)
    print(" TRACK 1/3: PISANITIZER DIRECT ATTACK COMPLETION (Reaching 100% full 1,100 samples)")
    print("#" * 80)
    for ds_path, expected in [("datasets/dolly_summarization.json", 200), ("datasets/msmarco_rag.json", 100)]:
        run_single_unit(
            dataset_path=ds_path,
            expected_samples=expected,
            attack="direct",
            defense="pisanitizer",
            exp_name="pisanitizer",
            seed=42,
        )

    # -------------------------------------------------------------------------
    # TRACK 2: Knowledge Corruption (B4, Table 4) across PromptGuard, DataFilter, PISanitizer
    # -------------------------------------------------------------------------
    print("\n" + "#" * 80)
    print(" TRACK 2/3: KNOWLEDGE CORRUPTION (B4, Table 4) DEFENSE EVALUATIONS (300 Samples Each)")
    print("#" * 80)
    # Notice: PIGuard on KC is ALREADY complete (300/300) in piguard_kc!
    for defense_name in ["promptguard", "datafilter", "pisanitizer"]:
        print(f"\n--- Defense {defense_name.upper()} on Knowledge Corruption (300 Samples) ---")
        exp_name = f"{defense_name}_kc"
        for ds_path, expected in KC_DATASETS:
            run_single_unit(
                dataset_path=ds_path,
                expected_samples=expected,
                attack="none",
                defense=defense_name,
                exp_name=exp_name,
                seed=42,
            )

    # -------------------------------------------------------------------------
    # TRACK 3: Combined Multi-Vector Attack (B2, Table 2) across Remaining Defenses (1,100 Samples Each)
    # -------------------------------------------------------------------------
    print("\n" + "#" * 80)
    print(" TRACK 3/3: COMBINED MULTI-VECTOR ATTACK (B2, Table 2) DEFENSE EVALUATIONS")
    print("#" * 80)
    # Notice: PIGuard on Combined is ALREADY complete (1,100/1,100) in piguard_combined!
    for defense_name in ["promptguard", "pisanitizer", "datafilter"]:
        print(f"\n--- Defense {defense_name.upper()} on Combined Multi-Vector Attack (1,100 Samples) ---")
        exp_name = f"{defense_name}_combined"
        for ds_path, expected in CORE_DATASETS:
            run_single_unit(
                dataset_path=ds_path,
                expected_samples=expected,
                attack="combined",
                defense=defense_name,
                exp_name=exp_name,
                seed=42,
            )

    # Final summary check
    state = load_state()
    total_tasks = len(state.get("tasks", {}))
    completed_tasks = sum(1 for t in state.get("tasks", {}).values() if t.get("status") == "completed")
    print("\n" + "=" * 80)
    print(f" [ALL DONE] EVALUATION SUITE COMPLETE! ({completed_tasks}/{total_tasks} tasks marked completed)")
    print("=" * 80)


if __name__ == "__main__":
    run_all_defense_evaluations()
