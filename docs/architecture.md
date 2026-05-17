# Architecture

LogShield AI classifies HTTP/request-derived logs for Log4Shell exploitation attempts.

```text
HTTP Requests / Access Logs
  -> Log Collector
  -> Canonicalization Engine
  -> Character Feature Builder
  -> Regex Baseline + BiLSTM Models
  -> Neural Risk Score
  -> API, Dashboard, Live Alerts, Reports
```

The detector is deliberately scoped to request-visible exploitation attempts. It is not a generic Security Information and Event Management (SIEM) platform and does not attempt host forensics.

## Components

- `src/detector/canonicalizer.py`: normalizes obfuscated lookup expressions and extracts canonical signals.
- `src/detector/regex_baseline.py`: signature baseline over raw and normalized logs.
- `src/detector/models/`: BiLSTM, BiLSTM with attention, and optional Char-CNN builders.
- `scripts/`: dataset construction, importers, training, evaluation, ablation, live monitoring, and scanning.
- `api/`: FastAPI service for single and batch predictions.
- `dashboard/`: Streamlit interface for demo and analysis.
