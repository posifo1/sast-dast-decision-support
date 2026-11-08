"""
score_strategies.py - score SAST (Semgrep), DAST (OWASP ZAP) and the combined
strategy against the OWASP Benchmark v1.2 ground truth.

A test case counts as FLAGGED by a tool if the tool reported at least one finding
for that test case (Semgrep: in its source file; ZAP: at its URL) whose CWE
matches the test case's CWE category. COMBINED = flagged by SAST or DAST (union).

Outputs:
  strategy_scores.csv  one row per CWE x strategy (TP, FP, FN, TN, P, R, F1, ...)
  per_test_flags.csv   one row per test case with the SAST/DAST/COMBINED flags,
                       used for the paired statistical tests (McNemar)

Usage:
  python score_strategies.py semgrep_pilot.json zap_report.json expectedresults-1.2.csv
"""
import json, re, sys
import pandas as pd

SCOPE = [22, 78, 89, 90, 327]
EQUIV = {327: {326, 327}}   # Semgrep tags DES/3DES rules as CWE-326
TEST = re.compile(r"(BenchmarkTest\d{5})")

def read_json(path):
    raw = open(path, "rb").read()
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return json.loads(raw.decode("cp1252", errors="replace"))

def semgrep_flags(path):
    flags = {}
    for res in read_json(path)["results"]:
        m = TEST.search(res["path"])
        if m:
            cwes = {int(c.group(1)) for s in res["extra"].get("metadata", {}).get("cwe", [])
                    if (c := re.match(r"CWE-(\d+)", s))}
            flags.setdefault(m.group(1), set()).update(cwes)
    return flags

def zap_flags(path):
    flags = {}
    for site in read_json(path).get("site", []):
        for alert in site.get("alerts", []):
            try:
                cwe = int(alert.get("cweid", -1))
            except ValueError:
                continue
            for inst in alert.get("instances", []):
                m = TEST.search(inst.get("uri", ""))
                if m:
                    flags.setdefault(m.group(1), set()).add(cwe)
    return flags

def load_truth(path):
    df = pd.read_csv(path, header=None, skiprows=1,
                     names=["test", "category", "real", "cwe"], dtype=str)
    df["real"] = df["real"].str.strip().str.lower() == "true"
    df["cwe"] = df["cwe"].str.strip().astype(int)
    return df[df["cwe"].isin(SCOPE)].reset_index(drop=True)

def hit(flags, test, cwe):
    return bool(flags.get(test, set()) & EQUIV.get(cwe, {cwe}))

def metrics(g, col):
    tp = int((g.real & g[col]).sum());  fp = int((~g.real & g[col]).sum())
    fn = int((g.real & ~g[col]).sum()); tn = int((~g.real & ~g[col]).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "Precision": round(p, 3),
            "Recall": round(r, 3), "F1": round(2 * p * r / (p + r), 3) if p + r else 0.0,
            "FPR": round(fpr, 3), "Youden": round(r - fpr, 3)}

def main(semgrep_path, zap_path, truth_path):
    truth = load_truth(truth_path)
    s, d = semgrep_flags(semgrep_path), zap_flags(zap_path)
    truth["SAST"] = [hit(s, t, c) for t, c in zip(truth.test, truth.cwe)]
    truth["DAST"] = [hit(d, t, c) for t, c in zip(truth.test, truth.cwe)]
    truth["COMBINED"] = truth.SAST | truth.DAST

    rows = []
    for cwe, g in list(truth.groupby("cwe")) + [("ALL", truth)]:
        for strat in ["SAST", "DAST", "COMBINED"]:
            rows.append({"CWE": f"CWE-{cwe}" if cwe != "ALL" else "All (pooled)",
                         "Cases": len(g), "Strategy": strat, **metrics(g, strat)})
    out = pd.DataFrame(rows)
    pd.set_option("display.width", 200)
    print(out.to_string(index=False))
    if not truth.DAST.any():
        print("\nWARNING: no ZAP finding matched any in-scope test case. Check that the "
              "spider reached the test pages and that the report is the traditional-json format.")
    out.to_csv("strategy_scores.csv", index=False)
    truth.to_csv("per_test_flags.csv", index=False)
    print("\nSaved strategy_scores.csv and per_test_flags.csv")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
