"""
run_all.py - runs the whole artefact pipeline in order.
Usage (from inside this folder):  python run_all.py
Needs semgrep_results.json, zap_report.json and expectedresults-1.2.csv in this folder.
"""
import subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NEEDED = ["semgrep_results.json", "zap_report.json", "expectedresults-1.2.csv"]
missing = [f for f in NEEDED if not (HERE / f).exists()]
if missing:
    sys.exit("Missing input file(s): " + ", ".join(missing) + ". Copy them into this folder first.")

STEPS = [
    ("Step 1 of 5: scoring SAST, DAST and combined against the ground truth",
     ["score_strategies.py", "semgrep_results.json", "zap_report.json", "expectedresults-1.2.csv"]),
    ("Step 2 of 5: chi-square tests across CWE categories (H2)", ["h2_test.py"]),
    ("Step 3 of 5: McNemar, Friedman and bootstrap tests (H1-H3)", ["hypothesis_tests.py", "per_test_flags.csv"]),
    ("Step 4 of 5: validating the decision-support programme (H4)", ["decision_framework.py", "validate", "--splits", "1000"]),
    ("Step 5 of 5: example recommendation", ["decision_framework.py", "recommend", "--cwe", "CWE-89", "--constraint", "Maximize Precision"]),
]
for title, cmd in STEPS:
    print("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78, flush=True)
    result = subprocess.run([sys.executable] + cmd, cwd=HERE)
    if result.returncode != 0:
        sys.exit(f"Stopped: '{' '.join(cmd)}' failed.")
print("\nAll steps completed. Results are in strategy_scores.csv, per_test_flags.csv and validation_report.csv.")
