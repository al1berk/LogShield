# Model Card

## Purpose

The models classify HTTP/request-derived log lines as benign or malicious for Log4Shell exploitation attempts.

## Input

One raw log line, usually containing request path, method, host, body, or headers.

## Output

The product detector returns a label, risk score, risk level, normalized log, detected patterns, explanation, model score breakdown, and latency.

Risk bands are fixed for product output: scores below `0.35` are benign, scores from `0.35` to below `0.70` are suspicious, and scores at or above `0.70` are malicious. Model-specific binary thresholds used in evaluation are calibrated on validation data and saved in `models/thresholds.json`.

## Training Data

Training uses controlled synthetic malicious payloads, generated benign web logs, Apache-format benign logs, and selected hard-negative benign examples. External validation data is not used for training.

## Evaluation Data

Evaluation uses standard test, unseen obfuscation test, adversarial evasion test, hard-negative test, external Honeynet/GreedyBear-style test, Splunk test, Fox-IT packet-capture-derived test, external benign Apache access-log test, blind manual test, and frozen OOD stress test files. The OOD stress split is not used for training, validation, threshold calibration, or model selection.

## Metrics

Accuracy, precision, recall, F1-score, Receiver Operating Characteristic Area Under the Curve (ROC-AUC), Precision-Recall Area Under the Curve (PR-AUC), false positive rate, false negative rate, latency, and throughput are reported.

## Known Failure Cases

The detector may miss new obfuscation strategies that neither canonicalization nor the training set cover. Hard-negative and external-format benign training reduce false positives on benign payload-like text and public benign Apache logs, but the frozen OOD stress split still shows a precision/recall tradeoff: Raw BiLSTM has the best final OOD F1 balance, while BiLSTM + Attention has the lowest OOD false-positive rate with lower malicious recall.

The canonical-signal BiLSTM variant is retained as an ablation model. If it underperforms after calibration, it should be discussed as evidence that explicit signals do not automatically improve generalization.

## Intended Use

Defensive detection engineering, lab demonstration, research prototyping, and analyst triage for request-visible Log4Shell attempts.

## Out-of-Scope Use

The model is not a proof of exploitation, not a patching substitute, not a generic malware detector, and not a full enterprise SIEM.
