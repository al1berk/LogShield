#!/usr/bin/env python3
"""Create an ablation table summarizing detector component value."""

from __future__ import annotations

import argparse

import _bootstrap  # noqa: F401
import pandas as pd

from detector.paths import RESULTS_DIR


ABLATIONS = [
    ("Raw text BiLSTM", "Baseline sequence model on unnormalized logs", "Raw BiLSTM"),
    ("Normalized text BiLSTM", "Tests canonicalization value", "Normalized BiLSTM"),
    ("BiLSTM with attention", "Tests attention pooling under evasion and false-positive stress", "BiLSTM + Attention"),
    ("Normalized text + canonical signal", "Tests explicit signal features", "BiLSTM + Signal"),
    ("Regex only", "Signature-based comparison", "Regex Baseline"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    comparison_path = RESULTS_DIR / "final_comparison.csv"
    if not comparison_path.exists():
        raise FileNotFoundError("Run scripts/evaluate_all.py before scripts/run_ablation.py")
    comparison = pd.read_csv(comparison_path)
    error_path = RESULTS_DIR / "error_analysis.csv"
    errors = pd.read_csv(error_path) if error_path.exists() else pd.DataFrame()
    rows = []
    for experiment, purpose, model in ABLATIONS:
        standard = comparison[(comparison["model"] == model) & (comparison["test_set"] == "test.csv")]
        unseen = comparison[(comparison["model"] == model) & (comparison["test_set"] == "unseen_obfuscation_test.csv")]
        adversarial = comparison[(comparison["model"] == model) & (comparison["test_set"] == "adversarial_evasion_test.csv")]
        ood_stress = comparison[(comparison["model"] == model) & (comparison["test_set"] == "ood_stress_test.csv")]
        hard = comparison[(comparison["model"] == model) & (comparison["test_set"] == "hard_negative_test.csv")]
        blind = comparison[(comparison["model"] == model) & (comparison["test_set"] == "blind_manual_test.csv")]
        model_errors = errors[errors["model"].eq(model)] if "model" in errors.columns else pd.DataFrame()
        rows.append(
            {
                "experiment": experiment,
                "purpose": purpose,
                "model": model,
                "test_f1": standard["f1"].iloc[0] if not standard.empty else float("nan"),
                "unseen_f1": unseen["f1"].iloc[0] if not unseen.empty else float("nan"),
                "adversarial_evasion_f1": adversarial["f1"].iloc[0] if not adversarial.empty else float("nan"),
                "ood_stress_f1": ood_stress["f1"].iloc[0] if not ood_stress.empty else float("nan"),
                "ood_stress_recall": ood_stress["recall"].iloc[0] if not ood_stress.empty else float("nan"),
                "ood_stress_fpr": ood_stress["fpr"].iloc[0] if not ood_stress.empty else float("nan"),
                "blind_manual_f1": blind["f1"].iloc[0] if not blind.empty else float("nan"),
                "hard_negative_fpr": hard["fpr"].iloc[0] if not hard.empty else float("nan"),
                "threshold": standard["threshold"].iloc[0] if not standard.empty and "threshold" in standard else float("nan"),
                "model_error_count": int(len(model_errors)),
                "expected_result": "Improves robustness or exposes a weakness under fair split evaluation.",
            }
        )
    output = RESULTS_DIR / "ablation_table.csv"
    pd.DataFrame(rows).to_csv(output, index=False)
    print(f"[+] Wrote {output}")


if __name__ == "__main__":
    main()
