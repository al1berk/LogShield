"""Helpers for turning external threat feeds into request-log observations."""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable
from typing import Any

from .canonicalizer import canonicalize


LOOKUP_TOKEN_PATTERNS = [
    re.compile(r"(%24%7b[^\s\"',]+)", re.IGNORECASE),
    re.compile(r"(\$\{[^\s\"',]*(?:jndi|ldap://|rmi://|dns://|ldaps://|lower:|upper:|env:|::-|:-)[^\s\"',]*\})", re.IGNORECASE),
]
HEADER_FIELD_MARKERS = {"@timestamp", "@version", "_id", "_index", "_score", "_type"}


def is_header_like(text: str) -> bool:
    """Return True when a CSV/Elasticsearch header row was supplied as data."""
    stripped = text.strip().lstrip("\ufeff").strip("\"'")
    if not stripped:
        return False
    try:
        cells = next(csv.reader([stripped]))
    except Exception:
        cells = stripped.split(",")
    normalized_cells = [cell.strip().strip("\"'").lower() for cell in cells[:12]]
    if normalized_cells[:2] == ["@timestamp", "@version"]:
        return True
    return normalized_cells[:1] == ["@timestamp"] and len(HEADER_FIELD_MARKERS & set(normalized_cells)) >= 3


def _flatten_json(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key in (
            "payload",
            "raw_log",
            "message",
            "request",
            "url",
            "uri",
            "user_agent",
            "http_user_agent",
            "requestFullURI",
            "requestURI",
        ):
            if key in value:
                yield from _flatten_json(value[key])
        for nested in value.values():
            if isinstance(nested, (dict, list)):
                yield from _flatten_json(nested)
    elif isinstance(value, list):
        for item in value:
            yield from _flatten_json(item)
    elif value is not None:
        yield str(value)


def _candidate_texts(text: str) -> list[str]:
    candidates = [text]
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None
    if parsed is not None:
        candidates.extend(_flatten_json(parsed))
    return candidates


def _extract_lookup_token(text: str) -> str | None:
    for pattern in LOOKUP_TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(1).strip().strip("\"'")
            signal = canonicalize(token).canonical_signal
            if signal["has_jndi"] and (signal["has_ldap"] or signal["has_rmi"] or signal["has_dns"] or signal["has_ldaps"]):
                return token
    return None


def _is_request_shaped(text: str) -> bool:
    lowered = text.lower().strip()
    return lowered.startswith(("get ", "post ", "put ", "delete ", "patch ", "head ", "options ", "request from "))


def extract_log4shell_observation(text: str) -> str | None:
    """Extract a real Log4Shell request observation from a feed row.

    External feeds often contain full Elasticsearch CSV exports. This function
    rejects schema/header rows and avoids storing the entire export row as a
    payload when a compact HTTP-like observation can be recovered.
    """
    raw = "" if text is None else str(text).strip()
    if not raw or is_header_like(raw):
        return None

    for candidate in _candidate_texts(raw):
        candidate = candidate.strip()
        if not candidate or is_header_like(candidate):
            continue
        token = _extract_lookup_token(candidate)
        if not token:
            continue
        if _is_request_shaped(candidate) and len(candidate) <= 500:
            return candidate
        return f"Request from User-Agent: {token} | Method: GET | Host: external-feed | Path: /"
    return None
