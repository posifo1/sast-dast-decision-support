"""
decision_framework.py - Decision-Support Framework (Sections 3.11-3.13, Hypothesis H4).

Recommends SAST, DAST or COMBINED testing for a language, CWE category and
operational constraint, from measured evidence rather than fixed assumptions.

Decision rule (Section 3.11)
  1. Identify the context (language, CWE, constraint).
  2. Retrieve the measured Precision / Recall / F1 for SAST, DAST and COMBINED.
  3. Take the metric the constraint prioritises (Maximize Precision -> Precision,
     Maximize Recall -> Recall, Balanced Performance -> F1). Strategies within the
     practical-significance threshold (5 percentage points) of the best score are
     treated as equivalent.
  4. Break ties by operational cost: SAST (seconds, no running application) <
     DAST (minutes, running application) < COMBINED (both).
  Resource Constrained: recommends SAST, because DAST could not run within 8 GB RAM
  (feasibility evidence, Section 4.5); not part of the accuracy validation.

Validation (Section 3.13, H4)
  The test cases for each CWE are split at random into two halves, stratified by
  ground-truth label. Recommendations are derived from one half; the empirically
  supported strategies (all within 5 pp of the best) are determined from the other.
  This is repeated over many random splits. The always-SAST baseline is scored the
  same way.

Usage
  python decision_framework.py recommend --cwe CWE-89 --constraint "Maximize Precision"
  python decision_framework.py validate [--splits 1000]
Requires per_test_flags.csv from score_strategies.py in the same folder.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "per_test_flags.csv"
STRATEGIES = ["SAST", "DAST", "COMBINED"]            # in order of operational cost
CONSTRAINT_METRIC = {"Maximize Precision": "Precision",
                     "Maximize Recall": "Recall",
                     "Balanced Performance": "F1"}
THRESHOLD = 0.05                                       # 5 pp practical significance
EVIDENCE_LANGUAGES = {"Java"}                          # OWASP Benchmark v1.2 is Java only
H4_TARGET = 80.0


def metrics(flag, real):
    tp = int((flag & real).sum()); fp = int((flag & ~real).sum()); fn = int((~flag & real).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"Precision": p, "Recall": r, "F1": 2 * p * r / (p + r) if p + r else 0.0}


def scores(cases):
    """Measured metrics for each strategy on a set of test cases."""
    return {s: metrics(cases[s].values, cases["real"].values) for s in STRATEGIES}


def supported(sc, metric):
    """Strategies within THRESHOLD of the best score (the empirically supported set)."""
    best = max(sc[s][metric] for s in STRATEGIES)
    return [s for s in STRATEGIES if sc[s][metric] >= best - THRESHOLD]


def decide(sc, constraint):
    """Recommend one strategy: the cheapest of the supported set."""
    if constraint == "Resource Constrained":
        return "SAST"
    return supported(sc, CONSTRAINT_METRIC[constraint])[0]


def load():
    if not EVIDENCE.exists():
        sys.exit(f"Evidence file not found: {EVIDENCE}. Run score_strategies.py first.")
    df = pd.read_csv(EVIDENCE)
    for col in ["real"] + STRATEGIES:
        df[col] = df[col].astype(bool)
    return df


def recommend(language, cwe, constraint):
    if language not in EVIDENCE_LANGUAGES:
        print(f"Insufficient evidence: no measured results for {language}.")
        return
    df = load()
    cwe_num = int(cwe.upper().replace("CWE-", "").split()[0])
    cases = df[df.cwe == cwe_num]
    if cases.empty:
        print(f"Insufficient evidence: CWE-{cwe_num} was not evaluated.")
        return
    sc = scores(cases)
    print(f"Context: {language}, CWE-{cwe_num}, {constraint}")
    for s in STRATEGIES:
        m = sc[s]
        print(f"  {s:<9} Precision {m['Precision']:.3f}  Recall {m['Recall']:.3f}  F1 {m['F1']:.3f}")
    print(f"Recommendation: {decide(sc, constraint)}")
    if constraint in CONSTRAINT_METRIC:
        print(f"Equivalent within {THRESHOLD*100:.0f} pp on {CONSTRAINT_METRIC[constraint]}: "
              f"{', '.join(supported(sc, CONSTRAINT_METRIC[constraint]))}")


def validate(n_splits, seed=2026):
    df = load()
    rng = np.random.default_rng(seed)
    contexts = [(c, k) for c in sorted(df.cwe.unique()) for k in CONSTRAINT_METRIC]
    acc, base, detail = [], [], {ctx: 0 for ctx in contexts}
    for _ in range(n_splits):
        train_idx, test_idx = [], []
        for _, g in df.groupby(["cwe", "real"]):          # stratified 50/50 split
            idx = rng.permutation(g.index.values)
            half = len(idx) // 2
            train_idx += list(idx[:half]); test_idx += list(idx[half:])
        train, test = df.loc[train_idx], df.loc[test_idx]
        hits = sast_hits = 0
        for cwe, constraint in contexts:
            rec = decide(scores(train[train.cwe == cwe]), constraint)
            truth = supported(scores(test[test.cwe == cwe]), CONSTRAINT_METRIC[constraint])
            hits += rec in truth; sast_hits += "SAST" in truth
            detail[(cwe, constraint)] += rec in truth
        acc.append(100 * hits / len(contexts)); base.append(100 * sast_hits / len(contexts))
    acc, base = np.array(acc), np.array(base)
    print(f"Validation: {len(contexts)} contexts x {n_splits} random 50/50 splits\n")
    print("Agreement with the held-out empirically supported strategy, by context:")
    for (cwe, constraint), n in detail.items():
        full = decide(scores(df[df.cwe == cwe]), constraint)
        print(f"  CWE-{cwe:<4} {constraint:<21} recommends {full:<9} agreement {100*n/n_splits:5.1f}%")
    print(f"\nFramework accuracy: mean {acc.mean():.1f}%, 95% interval "
          f"[{np.percentile(acc, 2.5):.1f}, {np.percentile(acc, 97.5):.1f}]%, "
          f">= {H4_TARGET:.0f}% in {100*(acc >= H4_TARGET).mean():.1f}% of splits")
    print(f"Always-SAST baseline: mean {base.mean():.1f}%, 95% interval "
          f"[{np.percentile(base, 2.5):.1f}, {np.percentile(base, 97.5):.1f}]%")
    print(f"H4 target (mean >= {H4_TARGET:.0f}%): {'MET' if acc.mean() >= H4_TARGET else 'NOT MET'}")
    pd.DataFrame({"framework_accuracy": acc, "baseline_accuracy": base}).to_csv(
        HERE / "validation_report.csv", index=False)
    print(f"Per-split results saved to {HERE / 'validation_report.csv'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("recommend")
    r.add_argument("--language", default="Java")
    r.add_argument("--cwe", required=True)
    r.add_argument("--constraint", required=True,
                   choices=list(CONSTRAINT_METRIC) + ["Resource Constrained"])
    v = sub.add_parser("validate")
    v.add_argument("--splits", type=int, default=1000)
    a = ap.parse_args()
    recommend(a.language, a.cwe, a.constraint) if a.cmd == "recommend" else validate(a.splits)
