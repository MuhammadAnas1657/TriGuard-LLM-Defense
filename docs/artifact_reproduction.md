# TriGuard v2 — Artifact Reproduction Guide

## 1. Environment Setup

```bash
# Clone or navigate to the workspace
cd "e:\project\hackathon and journal paper\TriGuard_v2"

# Activate Python environment (Python >= 3.10)
conda activate torch_py312

# Install TriGuard in editable mode with test dependencies
pip install -e .
pip install pytest pyyaml
```

## 2. Running Automated Security Unit Tests

```bash
# Set PYTHONPATH to src directory
$env:PYTHONPATH = "src"

# Execute all 26 security verification unit tests
python -m pytest tests/ -v
```

Expected result:
```text
============================= 26 passed in ~30s =============================
```

## 3. Generating Evaluation Tables & Metrics

```bash
# Recompute all summary tables directly from raw JSON files in results/real/
python evaluation/generate_main_table.py

# Generate transparent data audit manifest
python evaluation/audit_results.py
```

Outputs created:
- `results/summary/main_table.csv`: Complete comma-separated evaluation metrics.
- `results/summary/MAIN_EVALUATION_REPORT.md`: Formatted Markdown report comparing all 6 defenses.
- `results/summary/AUDIT_MANIFEST.md`: SHA-256 hashes and sample counts of all evaluated datasets.
- `paper/tables/table_main_comparison.tex`: Production-ready LaTeX table for conference submission.

