# SAST vs DAST: Comparative Evaluation and Decision-Support Programme

This repository contains the analysis scripts, scan configuration and decision-support programme for the MSc dissertation *A Comparative Evaluation of Static and Dynamic Analysis Techniques for Vulnerability Detection in Modern Software Systems* by Peter Osifo, University of Essex Online (2026).

The study compares Static Application Security Testing (SAST, using Semgrep) and Dynamic Application Security Testing (DAST, using OWASP ZAP), on their own and combined, against the known ground truth of the OWASP Benchmark for Java v1.2. The results feed a decision-support programme that recommends SAST, DAST or combined testing for a given vulnerability type (CWE) and testing priority.

## Repository contents

| File | Purpose |
| --- | --- |
| `run_all.py` | Runs every step below in order with one command: scoring, statistical tests, validation and an example recommendation. |
| `score_strategies.py` | Scores Semgrep, ZAP and the combined strategy against `expectedresults-1.2.csv` and writes per-category metrics and per-test-case flags (`per_test_flags.csv`). |
| `h2_test.py` | Chi-square tests of Semgrep performance across CWE categories (dissertation Table 9). |
| `hypothesis_tests.py` | Exact McNemar tests (H1), Friedman test (H2) and bootstrap confidence intervals (H3). |
| `decision_framework.py` | Decision-support programme: recommendations and held-out validation (H4). |
| `zap_plan.yaml` | OWASP ZAP Automation Framework plan used for the DAST scan (dissertation Appendix E). |
| `requirements.txt` | Python packages needed to run the scripts. |

### Data and results files

| File | Contents |
| --- | --- |
| `semgrep_results.json` | Raw Semgrep (SAST) scan output in JSON format. |
| `zap_report.json` | Raw OWASP ZAP (DAST) scan report in JSON format. |
| `expectedresults-1.2.csv` | Official OWASP Benchmark v1.2 ground-truth labels (from the OWASP Benchmark repository, GPL v2). |
| `per_test_flags.csv` | Per-test-case results for SAST, DAST and the combined strategy, produced by `score_strategies.py`. |
| `strategy_scores.csv` | Precision, recall and F1 for each strategy and CWE category, produced by `score_strategies.py`. |
| `validation_report.csv` | Per-split results of the held-out validation (H4), produced by `decision_framework.py`. |
| `run_all_output.txt` | Full console output of `run_all.py`, matching the results reported in Chapter 4. |

Because the raw scan outputs are included, all scoring, statistical tests and validation can be reproduced with `python run_all.py` alone, without repeating the scans.

## Evaluation scope

- **Benchmark:** OWASP Benchmark for Java v1.2, commit `bc5ffeb09fb18ab039806d84ca1f718c2e332c54`
- **CWE categories evaluated:** CWE-22, CWE-78, CWE-89, CWE-90 and CWE-327 (1,328 test cases: 688 vulnerable, 640 non-vulnerable)
- **Ground truth:** `expectedresults-1.2.csv`, supplied with the Benchmark repository

## Environment used

| Component | Version / specification |
| --- | --- |
| Platform | GitHub Codespaces, Linux VM, 4 CPU cores, 16 GB RAM |
| SAST tool | Semgrep CLI 1.180.0 |
| SAST rules | Open-source Semgrep Java rules, semgrep-rules commit `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9` (113 rules applied) |
| Application server | Tomcat via Maven Cargo (`runBenchmark.sh`), HTTPS on port 8443, OpenJDK 25.0.4.1 |
| DAST tool | OWASP ZAP 2.17.0, stable Docker image (`ghcr.io/zaproxy/zaproxy:stable`) |
| ZAP add-ons | ascanrulesBeta v67, ascanrulesAlpha v58 |
| Container runtime | Docker 29.8.0 |

A first DAST attempt on an 8 GB local Windows machine failed because the Benchmark ran out of memory. A machine with at least 16 GB RAM is recommended.

## How to reproduce

### 1. Install the Python packages

```bash
pip install -r requirements.txt
```

### 2. Run the SAST scan (Semgrep)

Semgrep CLI 1.180.0 was run against the `src/main/java` directory of the OWASP Benchmark, using the open-source Semgrep Java rules (semgrep-rules commit `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9`), with JSON output saved as `semgrep_results.json`. The scan applied 113 rules to 2,766 files and produced 2,570 findings in 1 minute 20 seconds.

### 3. Start the Benchmark and run the DAST scan (ZAP)

Start the OWASP Benchmark from its own repository with `./runBenchmark.sh` and check that it is reachable at `https://localhost:8443/benchmark/`. Then, from the folder containing `zap_plan.yaml`, run:

```bash
docker run --rm --network host -v "$(pwd)":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -addoninstall ascanrulesBeta -addoninstall ascanrulesAlpha \
  -autorun /zap/wrk/zap_plan.yaml
```

### 4. Score the results and run the analysis

Make sure `semgrep_results.json`, `zap_report.json` and `expectedresults-1.2.csv` are in the same folder as the scripts (they are already included in this repository), then run:

```bash
python run_all.py
```

### 5. Use the decision-support programme

Get a recommendation for one context:

```bash
python decision_framework.py recommend --cwe CWE-89 --constraint "Maximize Precision"
```

The available constraints are `Maximize Precision`, `Maximize Recall`, `Balanced Performance` and `Resource Constrained`. Only Java is supported, because the evidence comes from the Java-only OWASP Benchmark.

Repeat the held-out validation (H4):

```bash
python decision_framework.py validate --splits 1000
```

This writes the per-split results to `validation_report.csv`.

## Responsible use

The OWASP Benchmark is a deliberately vulnerable application, and ZAP sends real attack traffic. Run the DAST scan only against your own local copy of the Benchmark, as was done in this study. Never point it at a system you do not own or have written permission to test (Computer Misuse Act 1990).

## Licences of third-party tools

The OWASP Benchmark is released under the GNU General Public License v2, the Semgrep engine under the GNU Lesser General Public License v2.1, the Semgrep rules under the Semgrep Rules License v1.0, and OWASP ZAP under the Apache License 2.0. The tools themselves are not included in this repository; only the Benchmark's ground-truth file (`expectedresults-1.2.csv`) is redistributed, under its GPL v2 licence.

## Citation

If you refer to this work, please cite:

Osifo, P. (2026) *A Comparative Evaluation of Static and Dynamic Analysis Techniques for Vulnerability Detection in Modern Software Systems*. MSc dissertation. University of Essex Online.
