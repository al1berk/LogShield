#!/usr/bin/env python3
"""Batch scan a text file of log lines."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import _bootstrap  # noqa: F401

from detector.inference import ProductDetector


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    detector = ProductDetector()
    rows = []
    for line_no, line in enumerate(Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        result = detector.predict(line)
        row = {"line": line_no, "raw_log": line, **result.as_dict()}
        rows.append(row)
        print(f"[{result.label.upper()}] score={result.score:.2f} {line}")
    if args.output:
        with Path(args.output).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["line", "raw_log"])
            writer.writeheader()
            writer.writerows(rows)


if __name__ == "__main__":
    main()
