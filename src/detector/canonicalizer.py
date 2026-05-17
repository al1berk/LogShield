"""Obfuscation-aware canonicalization for Log4Shell request logs."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote


PROTOCOLS = ("ldap", "rmi", "dns", "ldaps")


@dataclass(frozen=True)
class CanonicalizationResult:
    normalized_log: str
    canonical_signal: dict[str, bool]
    detected_patterns: list[str]
    obfuscation_type: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "normalized_log": self.normalized_log,
            "canonical_signal": self.canonical_signal,
            "detected_patterns": self.detected_patterns,
            "obfuscation_type": self.obfuscation_type,
        }


def _decode_unicode_escapes(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return re.sub(r"\\u([0-9a-fA-F]{4})", repl, text)


def _decode_repeated_url(text: str, max_passes: int = 4) -> tuple[str, int]:
    current = text
    passes = 0
    for _ in range(max_passes):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
        passes += 1
    return current, passes


def _resolve_lookup_expressions(text: str, max_rounds: int = 8) -> str:
    current = text
    rules: list[tuple[re.Pattern[str], Any]] = [
        (re.compile(r"\$\{\s*lower\s*:\s*([^{}]*)\}", re.IGNORECASE), lambda m: m.group(1).lower()),
        (re.compile(r"\$\{\s*upper\s*:\s*([^{}]*)\}", re.IGNORECASE), lambda m: m.group(1).upper()),
        (re.compile(r"\$\{\s*env\s*:[^{}]*:-([^{}]*)\}", re.IGNORECASE), lambda m: m.group(1)),
        (re.compile(r"\$\{\s*::-\s*([^{}]*)\}", re.IGNORECASE), lambda m: m.group(1)),
        (re.compile(r"\$\{\s*:-([^{}]*)\}", re.IGNORECASE), lambda m: m.group(1)),
    ]
    for _ in range(max_rounds):
        previous = current
        for pattern, repl in rules:
            current = pattern.sub(repl, current)
        if current == previous:
            break
    return current


def _cleanup(text: str) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def _detect_patterns(raw: str, normalized: str, url_decode_passes: int) -> tuple[dict[str, bool], list[str], str]:
    raw_lower = raw.lower()
    detected: list[str] = []
    signal = {
        "has_jndi": bool(re.search(r"j\s*[^a-z0-9]?\s*n\s*[^a-z0-9]?\s*d\s*[^a-z0-9]?\s*i|jndi", normalized)),
        "has_ldap": "ldap://" in normalized,
        "has_rmi": "rmi://" in normalized,
        "has_dns": "dns://" in normalized,
        "has_ldaps": "ldaps://" in normalized,
        "has_lookup_syntax": "${" in normalized or "${" in raw_lower,
        "has_nested_lookup": raw_lower.count("${") > 1,
        "has_url_encoding": url_decode_passes > 0 or bool(re.search(r"%25|%24|%7b|%3a|%2f", raw_lower)),
        "has_html_entity": html.unescape(raw) != raw,
        "has_unicode_escape": bool(re.search(r"\\u[0-9a-fA-F]{4}", raw)),
        "has_lower_upper_lookup": bool(re.search(r"\$\{\s*(lower|upper)\s*:", raw_lower)),
        "has_env_fallback": "${env:" in raw_lower or ":-" in raw_lower,
        "has_fragmented_jndi": bool(re.search(r"\$\{::-[jndi]\}", raw_lower)) or bool(re.search(r"j[^a-z0-9]+n[^a-z0-9]+d[^a-z0-9]+i", normalized)),
    }

    for key, present in signal.items():
        if present:
            detected.append(key.removeprefix("has_"))

    parts: list[str] = []
    if signal["has_url_encoding"]:
        parts.append("double_url_encoded" if url_decode_passes > 1 or "%25" in raw_lower else "url_encoded")
    if signal["has_unicode_escape"]:
        parts.append("unicode_escape")
    if signal["has_html_entity"]:
        parts.append("html_entity")
    if signal["has_nested_lookup"]:
        parts.append("nested_lookup")
    if signal["has_lower_upper_lookup"]:
        parts.append("lower_upper_lookup")
    if signal["has_env_fallback"]:
        parts.append("env_fallback")
    if signal["has_fragmented_jndi"]:
        parts.append("fragmented_tokens")
    if not parts and signal["has_jndi"]:
        parts.append("plain")
    if not parts:
        parts.append("none")

    return signal, detected, "_".join(parts)


def canonicalize(text: str) -> CanonicalizationResult:
    """Normalize a raw log line and extract Log4Shell-oriented signals."""
    raw = "" if text is None else str(text)
    decoded, url_passes = _decode_repeated_url(raw)
    decoded = html.unescape(decoded)
    decoded = _decode_unicode_escapes(decoded)
    decoded = _resolve_lookup_expressions(decoded)
    normalized = _cleanup(decoded)
    signal, detected, obfuscation_type = _detect_patterns(raw, normalized, url_passes)
    return CanonicalizationResult(
        normalized_log=normalized,
        canonical_signal=signal,
        detected_patterns=detected,
        obfuscation_type=obfuscation_type,
    )
