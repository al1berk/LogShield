#!/usr/bin/env python3
"""Import Splunk Log4Shell attack_data rows into the shared schema."""

from __future__ import annotations

import argparse
import csv
from datetime import date
from pathlib import Path

import _bootstrap  # noqa: F401
import pandas as pd

from detector.canonicalizer import canonicalize
from detector.dataset import DATASET_SCHEMA
from detector.external_ingest import extract_log4shell_observation
from detector.paths import PROCESSED_DATA_DIR

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


def import_splunk(input_path: str | None, url: str | None, output: Path) -> pd.DataFrame:
    if input_path:
        lines = Path(input_path).read_text(encoding="utf-8", errors="replace").splitlines()
    elif url and requests is not None:
        response = requests.get(url, timeout=12)
        response.raise_for_status()
        lines = response.text.splitlines()
    else:
        lines = []
    rows = []
    today = date.today().isoformat()
    for idx, raw in enumerate(lines, start=1):
        observation = extract_log4shell_observation(raw)
        if not observation:
            continue
        canonical = canonicalize(observation)
        rows.append(
            {
                "id": f"SP-{idx:06d}",
                "timestamp": today,
                "source": "splunk_attack_data",
                "raw_log": observation,
                "normalized_log": canonical.normalized_log,
                "label": 1,
                "attack_family": "log4shell",
                "obfuscation_type": canonical.obfuscation_type,
                "field": "access_log",
                "split": "external_splunk_test",
                "risk_level": "critical",
            }
        )
    df = pd.DataFrame(rows, columns=DATASET_SCHEMA)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False, quoting=csv.QUOTE_MINIMAL)
    return df


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input")
    parser.add_argument(
        "--url",
        default="https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/log4shell_exploitation/log4shell_correlation.log",
    )
    parser.add_argument("--output", default=str(PROCESSED_DATA_DIR / "external_splunk_test.csv"))
    args = parser.parse_args()
    df = import_splunk(args.input, args.url, Path(args.output))
    print(f"[+] Imported {len(df)} Splunk rows")


if __name__ == "__main__":
    main()
