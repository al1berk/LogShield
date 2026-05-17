# Submission Checklist

## Included Deliverables

- IEEE-style paper: `paper/log4shell_bilstm_ieee.pdf`
- Source code: `src/`, `scripts/`, `api/`, `dashboard/`, `demo/`, `docker/`
- Processed datasets: `data/processed/`
- Dataset metadata: `data/metadata/`
- Trained model artifacts: `models/bilstm_original.h5`, `models/bilstm_normalized.h5`, `models/bilstm_attention.h5`, `models/bilstm_signal.h5`
- Evaluation outputs: `results/final_comparison.csv`, `results/ablation_table.csv`, `results/error_analysis.csv`, `results/plots/`
- Result archive: `results.zip`

## Instructor Feedback Coverage

- Diverse obfuscation variants: URL encoding, double/triple encoding, nested lookups, lower/upper lookups, environment fallback, fragmented tokens, Unicode escape, zero-width characters, homoglyphs, HTML entities, context embedding, whitespace/comment injection, and field splitting.
- Benign vs malicious generation is documented in `README.md`, `docs/dataset_card.md`, and `scripts/build_dataset.py`.
- Fair evaluation includes standard, unseen obfuscation, adversarial evasion, hard-negative, external malicious validation, external benign web-log validation, blind manual, and frozen OOD stress splits.
- Regex comparison is included in `results/final_comparison.csv` and the paper.
- Generalization is tested with `ood_stress_test.csv` after freezing regex rules, model weights, and thresholds.
- False positives are explicitly reported as a limitation, not hidden.

## Final Verification

- Run `make test` before submission.
- Run `python3 scripts/evaluate_all.py && python3 scripts/run_ablation.py && python3 scripts/export_report.py` after any dataset/model changes.
- Recompile `paper/log4shell_bilstm_ieee.tex` after paper edits.
