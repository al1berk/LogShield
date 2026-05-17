#!/usr/bin/env python3
"""Train raw, normalized, attention, or canonical-signal BiLSTM models."""

from __future__ import annotations

import argparse
import json
import os

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import _bootstrap  # noqa: F401
import numpy as np
import pandas as pd
from sklearn.utils.class_weight import compute_class_weight

from detector.dataset import load_training_frames
from detector.features import SIGNAL_KEYS, CharTokenizer, signal_matrix
from detector.models import build_bilstm, build_bilstm_attention
from detector.paths import METRICS_DIR, MODELS_DIR


MODEL_CONFIG = {
    "original": ("bilstm_original.h5", "training_history_original.json"),
    "normalized": ("bilstm_normalized.h5", "training_history_normalized.json"),
    "attention": ("bilstm_attention.h5", "training_history_attention.json"),
    "signal": ("bilstm_signal.h5", "training_history_signal.json"),
}


def _fit_tokenizer(train_df: pd.DataFrame, max_len: int) -> CharTokenizer:
    texts = train_df["raw_log"].astype(str).tolist() + train_df["normalized_log"].astype(str).tolist()
    tokenizer = CharTokenizer.fit(texts, max_len=max_len)
    tokenizer.save(MODELS_DIR / "tokenizer.pkl")
    with (MODELS_DIR / "tokenizer_meta.json").open("w", encoding="utf-8") as handle:
        json.dump({"vocab_size": tokenizer.vocab_size, "max_len": tokenizer.max_len, "signal_keys": SIGNAL_KEYS}, handle, indent=2)
    return tokenizer


def train_model(model_kind: str, epochs: int, batch_size: int, max_len: int, sample_limit: int | None = None, verbose: int = 0) -> None:
    from tensorflow import keras

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    train_df, val_df = load_training_frames()
    if sample_limit:
        train_df = train_df.sample(min(sample_limit, len(train_df)), random_state=42)
        val_df = val_df.sample(min(max(sample_limit // 4, 32), len(val_df)), random_state=42)
    tokenizer = _fit_tokenizer(train_df, max_len=max_len)
    text_column = "raw_log" if model_kind == "original" else "normalized_log"
    X_train = tokenizer.encode_many(train_df[text_column].astype(str))
    X_val = tokenizer.encode_many(val_df[text_column].astype(str))
    y_train = train_df["label"].astype(float).to_numpy()
    y_val = val_df["label"].astype(float).to_numpy()

    if model_kind == "attention":
        model = build_bilstm_attention(tokenizer.vocab_size, tokenizer.max_len)
        fit_train = X_train
        fit_val = X_val
    elif model_kind == "signal":
        model = build_bilstm(tokenizer.vocab_size, tokenizer.max_len, signal_dim=len(SIGNAL_KEYS), name="logshield_bilstm_signal")
        fit_train = [X_train, signal_matrix(train_df[text_column].astype(str))]
        fit_val = [X_val, signal_matrix(val_df[text_column].astype(str))]
    else:
        model = build_bilstm(tokenizer.vocab_size, tokenizer.max_len, name=f"logshield_bilstm_{model_kind}")
        fit_train = X_train
        fit_val = X_val

    classes = np.array([0.0, 1.0])
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_train)
    class_weight = {int(cls): float(weight) for cls, weight in zip(classes, weights)}
    model_file, history_file = MODEL_CONFIG[model_kind]
    callbacks = [
        keras.callbacks.EarlyStopping(monitor="val_loss", patience=3, restore_best_weights=True),
        keras.callbacks.ModelCheckpoint(MODELS_DIR / model_file, monitor="val_loss", save_best_only=True),
    ]
    history = model.fit(
        fit_train,
        y_train,
        validation_data=(fit_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=verbose,
    )
    model.save(MODELS_DIR / model_file)
    with (METRICS_DIR / history_file).open("w", encoding="utf-8") as handle:
        json.dump({key: [float(v) for v in values] for key, values in history.history.items()}, handle, indent=2)
    print(f"[+] Saved {model_kind} model to {MODELS_DIR / model_file}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=sorted(MODEL_CONFIG), default="normalized")
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--batch", type=int, default=64)
    parser.add_argument("--max-len", type=int, default=512)
    parser.add_argument("--sample-limit", type=int)
    parser.add_argument("--verbose", type=int, choices=[0, 1, 2], default=0)
    args = parser.parse_args()
    train_model(args.model, args.epochs, args.batch, args.max_len, args.sample_limit, args.verbose)


if __name__ == "__main__":
    main()
