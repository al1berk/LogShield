"""Dataset schema and loading helpers."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from .paths import PROCESSED_DATA_DIR


DATASET_SCHEMA = [
    "id",
    "timestamp",
    "source",
    "raw_log",
    "normalized_log",
    "label",
    "attack_family",
    "obfuscation_type",
    "field",
    "split",
    "risk_level",
]

REQUIRED_DATASETS = [
    "train.csv",
    "val.csv",
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


def validate_schema(df: pd.DataFrame) -> None:
    missing = [column for column in DATASET_SCHEMA if column not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")


def load_dataset(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    validate_schema(df)
    df["label"] = df["label"].astype(int)
    return df


def load_processed(name: str) -> pd.DataFrame:
    return load_dataset(PROCESSED_DATA_DIR / name)


def load_training_frames() -> tuple[pd.DataFrame, pd.DataFrame]:
    return load_processed("train.csv"), load_processed("val.csv")
