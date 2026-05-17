"""Product inference service used by CLI, API, and dashboard."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from .canonicalizer import canonicalize
from .features import SIGNAL_KEYS, CharTokenizer, signal_vector
from .paths import MODELS_DIR
from .regex_baseline import predict_one
from .threshold import label_from_score, load_threshold_config, risk_level


@dataclass(frozen=True)
class DetectionResult:
    label: str
    score: float
    risk_level: str
    normalized_log: str
    detected_patterns: list[str]
    explanation: str
    model_scores: dict[str, float]
    latency_ms: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "score": round(self.score, 6),
            "risk_level": self.risk_level,
            "normalized_log": self.normalized_log,
            "detected_patterns": self.detected_patterns,
            "explanation": self.explanation,
            "model_scores": {key: round(value, 6) for key, value in self.model_scores.items()},
            "latency_ms": round(self.latency_ms, 4),
        }


class ProductDetector:
    """Neural detector with graceful regex fallback when model artifacts are absent."""

    def __init__(self, model_name: str = "bilstm_original", models_dir: str | Path = MODELS_DIR):
        self.model_name = model_name
        self.models_dir = Path(models_dir)
        self.tokenizer: CharTokenizer | None = None
        self.models: dict[str, Any] = {}
        self._load_assets()

    def _load_assets(self) -> None:
        tokenizer_path = self.models_dir / "tokenizer.pkl"
        if tokenizer_path.exists():
            self.tokenizer = CharTokenizer.load(tokenizer_path)

        try:
            from tensorflow import keras
        except ImportError:
            return

        model_files = {
            "bilstm_original": "bilstm_original.h5",
            "bilstm_normalized": "bilstm_normalized.h5",
            "bilstm_attention": "bilstm_attention.h5",
            "bilstm_signal": "bilstm_signal.h5",
        }
        for name, filename in model_files.items():
            path = self.models_dir / filename
            if path.exists():
                self.models[name] = keras.models.load_model(path, compile=False)

    def _model_score(self, model_key: str, text: str, normalized: str) -> float | None:
        model = self.models.get(model_key)
        if model is None or self.tokenizer is None:
            return None
        model_text = text if model_key == "bilstm_original" else normalized
        encoded = self.tokenizer.encode_many([model_text])
        if len(getattr(model, "inputs", [])) > 1:
            pred = model.predict([encoded, np.expand_dims(signal_vector(model_text), axis=0)], verbose=0)
        else:
            pred = model.predict(encoded, verbose=0)
        return float(pred.flatten()[0])

    def predict(self, raw_log: str) -> DetectionResult:
        start = time.perf_counter()
        canonical = canonicalize(raw_log)
        regex = predict_one(raw_log)
        scores: dict[str, float] = {"regex": regex.score}

        for model_key in ("bilstm_original", "bilstm_normalized", "bilstm_attention", "bilstm_signal"):
            model_score = self._model_score(model_key, raw_log, canonical.normalized_log)
            if model_score is not None:
                scores[model_key] = model_score

        if self.model_name == "regex":
            final_score = regex.score
        else:
            selected_model = self.model_name if self.model_name in scores else "bilstm_original"
            final_score = scores.get(selected_model, regex.score)

        latency_ms = (time.perf_counter() - start) * 1000.0
        label = label_from_score(final_score)
        explanation = _build_explanation(canonical.detected_patterns, label)
        return DetectionResult(
            label=label,
            score=float(final_score),
            risk_level=risk_level(final_score),
            normalized_log=canonical.normalized_log,
            detected_patterns=canonical.detected_patterns,
            explanation=explanation,
            model_scores=scores,
            latency_ms=latency_ms,
        )

    def predict_batch(self, logs: list[str]) -> list[DetectionResult]:
        return [self.predict(log) for log in logs]

    def metrics(self) -> dict[str, Any]:
        return {
            "loaded_models": sorted(self.models.keys()),
            "tokenizer_loaded": self.tokenizer is not None,
            "signal_keys": SIGNAL_KEYS,
            "thresholds": load_threshold_config(self.models_dir / "thresholds.json"),
            "fallback": "regex" if not self.models else self.model_name,
        }


def _build_explanation(patterns: list[str], label: str) -> str:
    if label == "benign":
        return "No Log4Shell lookup pattern was found after canonicalization."
    if "jndi" in patterns:
        return "The log contains a Java Naming and Directory Interface lookup pattern after canonicalization."
    if "url_encoding" in patterns or "nested_lookup" in patterns:
        return "The log contains suspicious obfuscation features associated with Log4Shell payloads."
    return "The detector assigned elevated risk based on combined signature and model evidence."
