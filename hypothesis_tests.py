"""
hypothesis_tests.py - statistical tests for H1, H2 (SAST vs DAST across CWEs) and H3,
using the paired per-test-case flags written by score_strategies.py.
Usage: python hypothesis_tests.py per_test_flags.csv
"""
import sys
import numpy as np
import pandas as pd
from scipy.stats import binomtest, friedmanchisquare

ORDER = [22, 78, 89, 90, 327]

def mcnemar(a, b):
    """Exact McNemar test on paired booleans a, b. Returns (b_only_a, b_only_b, p)."""
    n01 = int((a & ~b).sum()); n10 = int((~a & b).sum())
    n = n01 + n10
    p = binomtest(n01, n, 0.5).pvalue if n else 1.0
    return n01, n10, p

def f1(flag, real):
    tp = (flag & real).sum(); fp = (flag & ~real).sum(); fn = (~flag & real).sum()
    return 2 * tp / (2 * tp + fp + fn) if tp else 0.0

df = pd.read_csv(sys.argv[1])
rng = np.random.default_rng(2026)

print("H1: SAST vs DAST, exact McNemar tests (paired by test case)")
print("Recall = vulnerable cases only; FPR = non-vulnerable cases only\n")
rows = []
for cwe in ORDER + ["ALL"]:
    g = df if cwe == "ALL" else df[df.cwe == cwe]
    v, s = g[g.real], g[~g.real]
    r_sast_only, r_dast_only, p_r = mcnemar(v.SAST, v.DAST)
    f_sast_only, f_dast_only, p_f = mcnemar(s.SAST, s.DAST)
    rows.append({"CWE": "All" if cwe == "ALL" else f"CWE-{cwe}",
                 "Recall SAST": round(v.SAST.mean(), 3), "Recall DAST": round(v.DAST.mean(), 3),
                 "Recall: SAST-only / DAST-only": f"{r_sast_only} / {r_dast_only}", "p (recall)": p_r,
                 "FPR SAST": round(s.SAST.mean(), 3), "FPR DAST": round(s.DAST.mean(), 3),
                 "FP: SAST-only / DAST-only": f"{f_sast_only} / {f_dast_only}", "p (FPR)": p_f})
h1 = pd.DataFrame(rows)
pd.set_option("display.width", 250); pd.set_option("display.float_format", lambda x: f"{x:.2e}" if x < 0.001 else f"{x:.3f}")
print(h1.to_string(index=False), "\n")

print("H2: F1 by CWE and strategy; Friedman test across the five CWE blocks")
f1s = pd.DataFrame({s: [f1(df[df.cwe == c][s], df[df.cwe == c].real) for c in ORDER]
                    for s in ["SAST", "DAST", "COMBINED"]}, index=[f"CWE-{c}" for c in ORDER])
f1s["SAST - DAST (pp)"] = ((f1s.SAST - f1s.DAST) * 100).round(1)
print(f1s.round(3).to_string())
stat, p = friedmanchisquare(f1s.SAST, f1s.DAST, f1s.COMBINED)
w = stat / (len(ORDER) * (3 - 1))
print(f"Friedman chi2(2) = {stat:.2f}, p = {p:.3f}, Kendall's W = {w:.3f}\n")

print("H3: combined vs best single strategy, F1 difference with 95% bootstrap CI (10,000 resamples, stratified by CWE)")
def boot_diff(g, best):
    idx_by = [np.flatnonzero(g.cwe.values == c) for c in sorted(g.cwe.unique())]
    real, comb, single = g.real.values, g.COMBINED.values, g[best].values
    diffs = np.empty(10000)
    for i in range(10000):
        idx = np.concatenate([rng.choice(ix, len(ix)) for ix in idx_by])
        diffs[i] = f1(comb[idx], real[idx]) - f1(single[idx], real[idx])
    return np.percentile(diffs, [2.5, 97.5])
for cwe in ORDER + ["ALL"]:
    g = df if cwe == "ALL" else df[df.cwe == cwe]
    best = max(["SAST", "DAST"], key=lambda s: f1(g[s], g.real))
    d = f1(g.COMBINED, g.real) - f1(g[best], g.real)
    lo, hi = boot_diff(g, best)
    label = "All" if cwe == "ALL" else f"CWE-{cwe}"
    print(f"{label:<8} best single = {best:<5} combined - best = {d*100:+.1f} pp  95% CI [{lo*100:+.1f}, {hi*100:+.1f}] pp"
          + ("  meets 5 pp threshold" if lo * 100 >= 5 else ""))
