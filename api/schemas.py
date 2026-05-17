"""API request and response schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PredictRequest(BaseModel):
    log: str = Field(..., min_length=1)


class BatchPredictRequest(BaseModel):
    logs: list[str] = Field(..., min_length=1)


class PredictResponse(BaseModel):
    label: str
    score: float
    risk_level: str
    normalized_log: str
    detected_patterns: list[str]
    explanation: str
    model_scores: dict[str, float]
    latency_ms: float
