"""Threshold calibration utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import f1_score

from .paths import MODELS_DIR


DEFAULT_BINARY_THRESHOLDS = {
    "regex": 0.70,
    "bilstm_original": 0.50,
    "bilstm_normalized": 0.50,
    "bilstm_attention": 0.50,
    "bilstm_signal": 0.50,
}
DEFAULT_RISK_BANDS = {"benign_max_exclusive": 0.35, "suspicious_min": 0.35, "malicious_min": 0.70}


def risk_level(score: float) -> str:
    if score >= 0.70:
        return "critical"
    if score >= 0.35:
        return "suspicious"
    return "low"


def label_from_score(score: float) -> str:
    if score >= 0.70:
        return "malicious"
    if score >= 0.35:
        return "suspicious"
    return "benign"


def calibrate_threshold(y_true: np.ndarray, y_score: np.ndarray, preferred: float = 0.50) -> float:
    thresholds = np.linspace(0.05, 0.95, 181)
    scores = [f1_score(y_true, y_score >= threshold, zero_division=0) for threshold in thresholds]
    best = np.max(scores)
    candidates = thresholds[np.isclose(scores, best)]
    return float(candidates[int(np.argmin(np.abs(candidates - preferred)))])


def default_threshold_config() -> dict[str, Any]:
    return {
        "binary_thresholds": dict(DEFAULT_BINARY_THRESHOLDS),
        "calibrated_thresholds": dict(DEFAULT_BINARY_THRESHOLDS),
        "risk_bands": dict(DEFAULT_RISK_BANDS),
        "validation_metrics": {},
        "generated_at": None,
    }


def load_threshold_config(path: str | Path = MODELS_DIR / "thresholds.json") -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return default_threshold_config()
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if "binary_thresholds" not in payload:
        config = default_threshold_config()
        config["binary_thresholds"].update({key: float(value) for key, value in payload.items()})
        config["calibrated_thresholds"].update({key: float(value) for key, value in payload.items()})
        return config
    payload["binary_thresholds"] = {key: float(value) for key, value in payload.get("binary_thresholds", {}).items()}
    payload["calibrated_thresholds"] = {key: float(value) for key, value in payload.get("calibrated_thresholds", {}).items()}
    payload.setdefault("risk_bands", dict(DEFAULT_RISK_BANDS))
    payload.setdefault("validation_metrics", {})
    return payload


def load_thresholds(path: str | Path = MODELS_DIR / "thresholds.json") -> dict[str, float]:
    return dict(load_threshold_config(path)["binary_thresholds"])


def model_threshold(model_key: str, path: str | Path = MODELS_DIR / "thresholds.json") -> float:
    thresholds = load_thresholds(path)
    return float(thresholds.get(model_key, DEFAULT_BINARY_THRESHOLDS.get(model_key, 0.50)))


def save_thresholds(thresholds: dict[str, Any], path: str | Path = MODELS_DIR / "thresholds.json") -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(thresholds, handle, indent=2, sort_keys=True)
