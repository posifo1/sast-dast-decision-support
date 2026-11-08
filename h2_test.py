"""
h2_test.py - chi-square tests of whether Semgrep (SAST) performance differs across
the five CWE categories (H2). Effect size: Cramer's V.
Usage: python h2_test.py   (reads strategy_scores.csv written by score_strategies.py)
"""
import numpy as np
import pandas as pd
from scipy.stats import chi2_contingency

SCOPE = ["CWE-22", "CWE-78", "CWE-89", "CWE-90", "CWE-327"]

def test(df, a, b, label):
    table = df[[a, b]].to_numpy()
    chi2, p, dof, expected = chi2_contingency(table)
    v = np.sqrt(chi2 / (table.sum() * (min(table.shape) - 1)))
    low = (expected < 5).sum()
    print(f"{label:<38} chi2({dof}) = {chi2:7.2f}, p = {p:.2e}, Cramer's V = {v:.3f}"
          + (f"  [{low} cells with expected count < 5]" if low else ""))

df = pd.read_csv("strategy_scores.csv")
df = df[(df.Strategy == "SAST") & (df.CWE.isin(SCOPE))].set_index("CWE")
df["Correct"] = df.TP + df.TN
df["Incorrect"] = df.FP + df.FN
print(df[["TP", "FP", "FN", "TN", "Precision", "Recall", "F1"]], "\n")
test(df, "Correct", "Incorrect", "Overall classification correctness")
test(df, "TP", "FN", "Recall (detected vs missed)")
test(df, "FP", "TN", "False positive rate")
