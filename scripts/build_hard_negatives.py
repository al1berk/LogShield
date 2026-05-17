#!/usr/bin/env python3
"""Generate hard-negative benign examples with the shared schema."""

from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

try:
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    from scripts import _bootstrap  # noqa: F401
import pandas as pd

from detector.dataset import DATASET_SCHEMA
from detector.paths import PROCESSED_DATA_DIR

try:
    from build_dataset import _hard_negative_variants, _record
except ImportError:  # pragma: no cover
    from scripts.build_dataset import _hard_negative_variants, _record


def main() -> None:
    rows = []
    examples = _hard_negative_variants()
    for idx in range(1, 181):
        raw, family = examples[(idx - 1) % len(examples)]
        raw = f"{raw} trace_id=standalone-hardneg-{idx:04d}"
        row = _record(idx, "hard_negative", raw, 0, family, "mixed", "hard_negative_test", "low", family)
        row["id"] = f"HN-{idx:06d}"
        row["timestamp"] = date.today().isoformat()
        rows.append(row)
    df = pd.DataFrame(rows, columns=DATASET_SCHEMA)
    output = PROCESSED_DATA_DIR / "hard_negative_test.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False, quoting=csv.QUOTE_MINIMAL)
    print(f"[+] Wrote {output}")


if __name__ == "__main__":
    main()
