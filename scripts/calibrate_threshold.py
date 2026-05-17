#!/usr/bin/env python3
"""Calibrate detector thresholds on validation data."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap  # noqa: F401
import numpy as np

from detector.dataset import load_processed
from detector.features import CharTokenizer, signal_matrix
from detector.metrics import binary_metrics
from detector.paths import MODELS_DIR
from detector.regex_baseline import predict_scores
from detector.threshold import DEFAULT_BINARY_THRESHOLDS, DEFAULT_RISK_BANDS, calibrate_threshold, save_thresholds


MODEL_FILES = {
    "bilstm_original": ("bilstm_original.h5", "raw_log"),
    "bilstm_normalized": ("bilstm_normalized.h5", "normalized_log"),
    "bilstm_attention": ("bilstm_attention.h5", "normalized_log"),
    "bilstm_signal": ("bilstm_signal.h5", "normalized_log"),
}


def _load_keras_model(path: Path):
    if not path.exists():
        return None
    from tensorflow import keras

    return keras.models.load_model(path, compile=False)


def _score_keras(model, tokenizer: CharTokenizer, texts: list[str], signal: bool = False) -> np.ndarray:
    encoded = tokenizer.encode_many(texts)
    if signal:
        preds = model.predict([encoded, signal_matrix(texts)], verbose=0)
    else:
        preds = model.predict(encoded, verbose=0)
    return preds.flatten().astype(float)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    val_df = load_processed("val.csv")
    y = val_df["label"].to_numpy()
    validation_metrics = {}
    calibrated_thresholds = {}
    binary_thresholds = dict(DEFAULT_BINARY_THRESHOLDS)

    regex_scores = np.asarray(predict_scores(val_df["raw_log"].astype(str).tolist()))
    calibrated_thresholds["regex"] = calibrate_threshold(y, regex_scores, preferred=0.70)
    binary_thresholds["regex"] = calibrated_thresholds["regex"]
    validation_metrics["regex"] = binary_metrics(y, regex_scores, threshold=binary_thresholds["regex"])

    tokenizer = CharTokenizer.load(MODELS_DIR / "tokenizer.pkl") if (MODELS_DIR / "tokenizer.pkl").exists() else None
    if tokenizer is not None:
        for key, (filename, column) in MODEL_FILES.items():
            model = _load_keras_model(MODELS_DIR / filename)
            if model is None:
                continue
            texts = val_df[column].astype(str).tolist()
            scores = _score_keras(model, tokenizer, texts, signal=key == "bilstm_signal")
            calibrated_thresholds[key] = calibrate_threshold(y, scores, preferred=0.50)
            binary_thresholds[key] = calibrated_thresholds[key]
            validation_metrics[key] = binary_metrics(y, scores, threshold=binary_thresholds[key])

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "binary_thresholds": binary_thresholds,
        "calibrated_thresholds": calibrated_thresholds,
        "risk_bands": DEFAULT_RISK_BANDS,
        "validation_metrics": validation_metrics,
        "notes": {
            "selection": "Thresholds maximize validation F1 with ties resolved toward the model default.",
        },
    }
    save_thresholds(payload, path=args.output or MODELS_DIR / "thresholds.json")
    print(f"[+] Saved thresholds to {args.output or MODELS_DIR / 'thresholds.json'}")


if __name__ == "__main__":
    main()
