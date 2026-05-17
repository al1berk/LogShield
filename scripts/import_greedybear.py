#!/usr/bin/env python3
"""Import GreedyBear/Log4Pot-style feed data into the shared schema."""

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


def _read_lines(input_path: str | None, url: str | None) -> list[str]:
    if input_path:
        return Path(input_path).read_text(encoding="utf-8", errors="replace").splitlines()
    if url and requests is not None:
        response = requests.get(url, timeout=12)
        response.raise_for_status()
        return response.text.splitlines()
    return []


def import_feed(input_path: str | None, url: str | None, output: Path) -> pd.DataFrame:
    rows = []
    today = date.today().isoformat()
    for idx, line in enumerate(_read_lines(input_path, url), start=1):
        payload = extract_log4shell_observation(line)
        if not payload:
            continue
        canonical = canonicalize(payload)
        rows.append(
            {
                "id": f"GB-{idx:06d}",
                "timestamp": today,
                "source": "greedybear_log4pot",
                "raw_log": payload,
                "normalized_log": canonical.normalized_log,
                "label": 1,
                "attack_family": "log4shell",
                "obfuscation_type": canonical.obfuscation_type,
                "field": "honeypot_feed",
                "split": "external_greedybear_test",
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
    parser.add_argument("--url")
    parser.add_argument("--output", default=str(PROCESSED_DATA_DIR / "external_greedybear_test.csv"))
    args = parser.parse_args()
    df = import_feed(args.input, args.url, Path(args.output))
    print(f"[+] Imported {len(df)} GreedyBear/Log4Pot rows")


if __name__ == "__main__":
    main()
