#!/usr/bin/env python3
"""Evaluate baselines and trained models on all required test sets."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import _bootstrap  # noqa: F401
import numpy as np
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay, PrecisionRecallDisplay, RocCurveDisplay

from detector.dataset import REQUIRED_DATASETS, load_processed
from detector.features import CharTokenizer, signal_matrix
from detector.metrics import benchmark_scores, binary_metrics
from detector.paths import METRICS_DIR, MODELS_DIR, PLOTS_DIR, PROCESSED_DATA_DIR, RESULTS_DIR
from detector.regex_baseline import predict_scores
from detector.threshold import load_thresholds

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:  # pragma: no cover
    plt = None


MODEL_FILES = {
    "Raw BiLSTM": ("bilstm_original", "bilstm_original.h5", "raw_log"),
    "Normalized BiLSTM": ("bilstm_normalized", "bilstm_normalized.h5", "normalized_log"),
    "BiLSTM + Attention": ("bilstm_attention", "bilstm_attention.h5", "normalized_log"),
    "BiLSTM + Signal": ("bilstm_signal", "bilstm_signal.h5", "normalized_log"),
}
TEST_FILES = [
    "test.csv",
    "unseen_obfuscation_test.csv",
    "adversarial_evasion_test.csv",
    "hard_negative_test.csv",
    "external_greedybear_test.csv",
    "external_splunk_test.csv",
    "external_foxit_pcap_test.csv",
    "external_benign_web_test.csv",
    "blind_manual_test.csv",
    "ood_stress_test.csv",
]


def _nan_metrics(model: str, test_set: str) -> dict[str, object]:
    return {
        "model": model,
        "test_set": test_set,
        "accuracy": math.nan,
        "precision": math.nan,
        "recall": math.nan,
        "f1": math.nan,
        "roc_auc": math.nan,
        "pr_auc": math.nan,
        "fpr": math.nan,
        "fnr": math.nan,
        "latency_ms": math.nan,
        "throughput_lps": math.nan,
        "tp": math.nan,
        "fp": math.nan,
        "tn": math.nan,
        "fn": math.nan,
        "positive_support": math.nan,
        "negative_support": math.nan,
        "threshold": math.nan,
        "metric_note": "model artifact or tokenizer unavailable",
    }


def _load_keras_model(path: Path):
    if not path.exists():
        return None
    try:
        from tensorflow import keras

        return keras.models.load_model(path, compile=False)
    except Exception:
        return None


def _score_keras(model, tokenizer: CharTokenizer, texts: list[str], signal: bool = False) -> tuple[np.ndarray, float]:
    def predict(batch: list[str]) -> list[float]:
        encoded = tokenizer.encode_many(batch)
        if signal:
            preds = model.predict([encoded, signal_matrix(batch)], verbose=0)
        else:
            preds = model.predict(encoded, verbose=0)
        return [float(value) for value in preds.flatten()]

    return benchmark_scores(predict, texts)


def _metric_note(y: np.ndarray) -> str:
    if len(np.unique(y)) < 2:
        return "single-class test set; ROC-AUC and PR-AUC are undefined"
    return ""


def _metric_row(model: str, test_set: str, y: np.ndarray, scores: np.ndarray, threshold: float, latency: float) -> dict[str, object]:
    return {
        "model": model,
        "test_set": test_set,
        **binary_metrics(y, scores, threshold=threshold, latency_ms=latency),
        "threshold": float(threshold),
        "metric_note": _metric_note(y),
    }


def evaluate() -> pd.DataFrame:
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    tokenizer = CharTokenizer.load(MODELS_DIR / "tokenizer.pkl") if (MODELS_DIR / "tokenizer.pkl").exists() else None
    thresholds = load_thresholds()
    loaded = {display: _load_keras_model(MODELS_DIR / model_file) for display, (_, model_file, _) in MODEL_FILES.items()}
    rows: list[dict[str, object]] = []
    primary_test_payload: tuple[np.ndarray, np.ndarray, float] | None = None
    prediction_frames: list[pd.DataFrame] = []

    for test_file in TEST_FILES:
        df = load_processed(test_file)
        y = df["label"].astype(int).to_numpy()
        raw_texts = df["raw_log"].astype(str).tolist()
        regex_scores, regex_latency = benchmark_scores(predict_scores, raw_texts)
        regex_threshold = thresholds.get("regex", 0.70)
        rows.append(_metric_row("Regex Baseline", test_file, y, regex_scores, regex_threshold, regex_latency))
        prediction_frames.append(_prediction_frame(df, "Regex Baseline", test_file, y, regex_scores, regex_threshold))

        for display, (key, _, column) in MODEL_FILES.items():
            model = loaded[display]
            if model is None or tokenizer is None:
                warnings.append(f"{display} unavailable for {test_file}; metrics left as NaN.")
                rows.append(_nan_metrics(display, test_file))
                continue
            scores, latency = _score_keras(model, tokenizer, df[column].astype(str).tolist(), signal=key == "bilstm_signal")
            threshold = thresholds.get(key, 0.50)
            rows.append(_metric_row(display, test_file, y, scores, threshold, latency))
            prediction_frames.append(_prediction_frame(df, display, test_file, y, scores, threshold))
            if display == "Raw BiLSTM" and test_file == "test.csv":
                primary_test_payload = (y, scores, threshold)

    result = pd.DataFrame(rows)
    comparison_columns = [
        "model",
        "test_set",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "pr_auc",
        "fpr",
        "fnr",
        "latency_ms",
        "throughput_lps",
        "tp",
        "fp",
        "tn",
        "fn",
        "positive_support",
        "negative_support",
        "threshold",
        "metric_note",
    ]
    result[comparison_columns].to_csv(RESULTS_DIR / "final_comparison.csv", index=False)
    with (METRICS_DIR / "evaluation_warnings.json").open("w", encoding="utf-8") as handle:
        json.dump(warnings, handle, indent=2)
    _write_error_analysis(prediction_frames)
    _plot_results(result, primary_test_payload)
    return result


def _prediction_frame(df: pd.DataFrame, model: str, test_set: str, y: np.ndarray, scores: np.ndarray, threshold: float) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "model": model,
            "id": df["id"],
            "test_set": test_set,
            "true_label": y,
            "pred_label": (scores >= threshold).astype(int),
            "score": scores,
            "threshold": threshold,
            "raw_log": df["raw_log"].astype(str),
            "normalized_log": df["normalized_log"].astype(str),
            "obfuscation_type": df["obfuscation_type"].astype(str),
            "source": df["source"].astype(str),
        }
    )


def _write_error_analysis(prediction_frames: list[pd.DataFrame]) -> None:
    rows = []
    for df in prediction_frames:
        for _, row in df.iterrows():
            pred = int(row["pred_label"])
            true = int(row["true_label"])
            if pred == true:
                continue
            error_type = "false_positive_keyword_only" if pred == 1 else "false_negative_unknown_obfuscation"
            if pred == 1 and "documentation" in str(row["obfuscation_type"]):
                error_type = "false_positive_documentation_example"
            if pred == 0 and "nested" in str(row["obfuscation_type"]):
                error_type = "false_negative_nested_lookup"
            if pred == 0 and "double" in str(row["obfuscation_type"]):
                error_type = "false_negative_double_encoding"
            rows.append(
                {
                    "model": row["model"],
                    "test_set": row["test_set"],
                    "id": row["id"],
                    "source": row["source"],
                    "raw_log": row["raw_log"],
                    "normalized_log": row["normalized_log"],
                    "true_label": true,
                    "pred_label": pred,
                    "score": row["score"],
                    "threshold": row["threshold"],
                    "error_type": error_type,
                    "obfuscation_type": row["obfuscation_type"],
                    "explanation": "Model score disagreed with the dataset label at the evaluation threshold.",
                }
            )
    columns = [
        "model",
        "test_set",
        "id",
        "source",
        "raw_log",
        "normalized_log",
        "true_label",
        "pred_label",
        "score",
        "threshold",
        "error_type",
        "obfuscation_type",
        "explanation",
    ]
    pd.DataFrame(rows, columns=columns).to_csv(RESULTS_DIR / "error_analysis.csv", index=False)


def _plot_results(result: pd.DataFrame, primary_test_payload: tuple[np.ndarray, np.ndarray, float] | None) -> None:
    if plt is None:
        return
    main = result[result["test_set"].eq("test.csv")].dropna(subset=["f1"])
    if not main.empty:
        ax = main.set_index("model")["f1"].sort_values().plot(kind="barh", figsize=(8, 4), color="#4C78A8")
        ax.set_title("Model F1 on Standard Test Set")
        ax.set_xlabel("F1")
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / "model_comparison_bar_chart.png", dpi=160)
        plt.close()

        ax = main.set_index("model")["latency_ms"].sort_values().plot(kind="barh", figsize=(8, 4), color="#F58518")
        ax.set_title("Latency per Log Line")
        ax.set_xlabel("Milliseconds")
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / "latency_comparison.png", dpi=160)
        plt.close()

    evasion = result[
        result["test_set"].isin(["test.csv", "adversarial_evasion_test.csv"])
        & result["model"].isin(["Regex Baseline", "Raw BiLSTM", "Normalized BiLSTM"])
    ].dropna(subset=["recall"])
    if not evasion.empty:
        pivot = evasion.pivot(index="model", columns="test_set", values="recall")
        pivot = pivot.rename(columns={"test.csv": "Standard Test", "adversarial_evasion_test.csv": "Adversarial Evasion"})
        ax = pivot.plot(kind="bar", figsize=(9, 5), color=["#4C78A8", "#E45756"])
        ax.set_title("Detection Recall on Standard vs Adversarial Payloads")
        ax.set_ylabel("Recall")
        ax.set_xlabel("")
        ax.set_ylim(0, 1.05)
        plt.xticks(rotation=20, ha="right")
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / "evasion_analysis.png", dpi=160)
        plt.close()

    stress = result[
        result["test_set"].eq("ood_stress_test.csv")
        & result["model"].isin(["Regex Baseline", "Raw BiLSTM", "Normalized BiLSTM"])
    ].dropna(subset=["recall", "fpr"])
    if not stress.empty:
        stress_plot = stress.set_index("model")[["recall", "fpr"]].rename(columns={"recall": "Malicious Recall", "fpr": "Benign FPR"})
        ax = stress_plot.plot(kind="bar", figsize=(8, 4.5), color=["#4C78A8", "#E45756"])
        ax.set_title("Frozen OOD Stress Test")
        ax.set_ylabel("Rate")
        ax.set_xlabel("")
        ax.set_ylim(0, 1.05)
        plt.xticks(rotation=20, ha="right")
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / "ood_stress_analysis.png", dpi=160)
        plt.close()

    if primary_test_payload is None:
        return
    y, scores, threshold = primary_test_payload
    preds = (scores >= threshold).astype(int)
    ConfusionMatrixDisplay.from_predictions(y, preds, display_labels=["Benign", "Malicious"], cmap="Blues")
    plt.title("Raw BiLSTM Confusion Matrix")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "confusion_matrix.png", dpi=160)
    plt.close()
    if len(np.unique(y)) == 2:
        RocCurveDisplay.from_predictions(y, scores)
        plt.title("Raw BiLSTM ROC Curve")
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / "roc_curve.png", dpi=160)
        plt.close()
        PrecisionRecallDisplay.from_predictions(y, scores)
        plt.title("Raw BiLSTM Precision-Recall Curve")
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / "precision_recall_curve.png", dpi=160)
        plt.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    missing = [name for name in REQUIRED_DATASETS if not (PROCESSED_DATA_DIR / name).exists()]
    if missing:
        raise FileNotFoundError(f"Missing processed datasets: {missing}. Run scripts/build_dataset.py first.")
    result = evaluate()
    print(result[["model", "test_set", "f1", "latency_ms"]].to_string(index=False))
    print(f"[+] Wrote {RESULTS_DIR / 'final_comparison.csv'}")


if __name__ == "__main__":
    main()
