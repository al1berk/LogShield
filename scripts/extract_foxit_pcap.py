#!/usr/bin/env python3
"""Extract HTTP request-like rows from Fox-IT Log4Shell PCAPs using tshark."""

from __future__ import annotations

import argparse
import csv
import subprocess
from datetime import date
from pathlib import Path

import _bootstrap  # noqa: F401
import pandas as pd

from detector.canonicalizer import canonicalize
from detector.dataset import DATASET_SCHEMA
from detector.paths import PROCESSED_DATA_DIR


def extract_pcap(pcap: Path, output: Path) -> pd.DataFrame:
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        "http.request",
        "-T",
        "fields",
        "-e",
        "frame.time",
        "-e",
        "ip.src",
        "-e",
        "http.request.method",
        "-e",
        "http.host",
        "-e",
        "http.request.uri",
        "-e",
        "http.user_agent",
    ]
    completed = subprocess.run(cmd, check=True, text=True, capture_output=True)
    rows = []
    today = date.today().isoformat()
    for idx, line in enumerate(completed.stdout.splitlines(), start=1):
        parts = (line.split("\t") + [""] * 6)[:6]
        frame_time, ip_src, method, host, uri, ua = parts
        raw = f"Request from {ip_src} User-Agent: {ua} | Method: {method} | Host: {host} | Path: {uri}"
        canonical = canonicalize(raw)
        label = 1 if canonical.canonical_signal["has_jndi"] else 0
        rows.append(
            {
                "id": f"FX-{idx:06d}",
                "timestamp": frame_time or today,
                "source": "foxit_pcap_http",
                "raw_log": raw,
                "normalized_log": canonical.normalized_log,
                "label": label,
                "attack_family": "log4shell" if label else "benign",
                "obfuscation_type": canonical.obfuscation_type,
                "field": "pcap_http",
                "split": "external_foxit_pcap_test",
                "risk_level": "critical" if label else "low",
            }
        )
    df = pd.DataFrame(rows, columns=DATASET_SCHEMA)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False, quoting=csv.QUOTE_MINIMAL)
    return df


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--output", default=str(PROCESSED_DATA_DIR / "external_foxit_pcap_test.csv"))
    args = parser.parse_args()
    df = extract_pcap(Path(args.pcap), Path(args.output))
    print(f"[+] Extracted {len(df)} Fox-IT PCAP HTTP rows")


if __name__ == "__main__":
    main()
