"""FastAPI application for LogShield AI."""

from __future__ import annotations

from fastapi import FastAPI

from .detector_service import get_detector
from .schemas import BatchPredictRequest, PredictRequest, PredictResponse

app = FastAPI(title="LogShield AI", version="1.0.0")


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "LogShield AI",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    return get_detector().predict(request.log).as_dict()


@app.post("/batch-predict", response_model=list[PredictResponse])
def batch_predict(request: BatchPredictRequest):
    return [result.as_dict() for result in get_detector().predict_batch(request.logs)]


@app.post("/explain", response_model=PredictResponse)
def explain(request: PredictRequest):
    return get_detector().predict(request.log).as_dict()


@app.get("/metrics")
def metrics():
    return get_detector().metrics()
