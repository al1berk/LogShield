"""Evaluation metrics for binary Log4Shell classifiers."""

from __future__ import annotations

import time
from collections.abc import Callable

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def safe_auc(metric_fn: Callable[[np.ndarray, np.ndarray], float], y_true: np.ndarray, y_score: np.ndarray) -> float:
    if len(np.unique(y_true)) < 2:
        return float("nan")
    return float(metric_fn(y_true, y_score))


def binary_metrics(y_true: np.ndarray, y_score: np.ndarray, threshold: float = 0.5, latency_ms: float = 0.0) -> dict[str, float]:
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score).astype(float)
    y_pred = (y_score >= threshold).astype(int)
    labels = [0, 1]
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=labels).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    positive_support = int(np.sum(y_true == 1))
    negative_support = int(np.sum(y_true == 0))
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": safe_auc(roc_auc_score, y_true, y_score),
        "pr_auc": safe_auc(average_precision_score, y_true, y_score),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "latency_ms": float(latency_ms),
        "throughput_lps": float(1000.0 / latency_ms) if latency_ms > 0 else 0.0,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "positive_support": positive_support,
        "negative_support": negative_support,
    }


def benchmark_scores(predict_fn: Callable[[list[str]], list[float]], texts: list[str]) -> tuple[np.ndarray, float]:
    start = time.perf_counter()
    scores = np.asarray(predict_fn(texts), dtype=float)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    latency_ms = elapsed_ms / max(len(texts), 1)
    return scores, latency_ms
