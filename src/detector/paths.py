"""Shared filesystem paths for the LogShield AI project."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
METADATA_DIR = DATA_DIR / "metadata"
MODELS_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "results"
METRICS_DIR = RESULTS_DIR / "metrics"
PLOTS_DIR = RESULTS_DIR / "plots"
PREDICTIONS_DIR = RESULTS_DIR / "predictions"
DEMO_DIR = PROJECT_ROOT / "demo"
DOCS_DIR = PROJECT_ROOT / "docs"


def ensure_project_dirs() -> None:
    """Create the product-level directory tree used by scripts."""
    for path in [
        RAW_DATA_DIR / "synthetic",
        RAW_DATA_DIR / "greedybear_log4pot",
        RAW_DATA_DIR / "foxit_pcaps",
        RAW_DATA_DIR / "splunk",
        RAW_DATA_DIR / "payload_corpora",
        RAW_DATA_DIR / "benign_logs",
        PROCESSED_DATA_DIR,
        METADATA_DIR,
        MODELS_DIR,
        METRICS_DIR,
        PLOTS_DIR,
        PREDICTIONS_DIR,
        DEMO_DIR / "logs",
    ]:
        path.mkdir(parents=True, exist_ok=True)
