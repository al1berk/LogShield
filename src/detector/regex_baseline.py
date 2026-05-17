"""Signature baseline for Log4Shell payload detection."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonicalizer import canonicalize


RAW_PATTERNS = [
    re.compile(r"\$\{\s*j\s*n\s*d\s*i\s*:", re.IGNORECASE),
    re.compile(r"jndi\s*:\s*(ldap|rmi|dns|ldaps)\s*://", re.IGNORECASE),
    re.compile(r"%24%7b", re.IGNORECASE),
    re.compile(r"%2524%257b", re.IGNORECASE),
    re.compile(r"\$\{\s*(lower|upper)\s*:", re.IGNORECASE),
    re.compile(r"\$\{\s*env\s*:[^{}]*:-", re.IGNORECASE),
    re.compile(r"\$\{::-[jndi]\}", re.IGNORECASE),
]
NORMALIZED_PATTERNS = [
    re.compile(r"\$\{\s*jndi\s*:\s*(ldap|rmi|dns|ldaps)\s*://", re.IGNORECASE),
    re.compile(r"jndi\s*:\s*(ldap|rmi|dns|ldaps)\s*://", re.IGNORECASE),
    re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE),
]
HARD_NEGATIVE_CONTEXT = re.compile(
    r"\\\$\{|escaped payload|as text|documentation page|blog article|security scanner report mentions|user searched|developer opened",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RegexResult:
    label: int
    score: float
    matched_patterns: list[str]
    normalized_log: str


def predict_one(raw_log: str) -> RegexResult:
    result = canonicalize(raw_log)
    hard_negative_context = bool(HARD_NEGATIVE_CONTEXT.search(str(raw_log)))
    matches: list[str] = []
    for pattern in RAW_PATTERNS:
        if pattern.search(str(raw_log)):
            matches.append(pattern.pattern)
    for pattern in NORMALIZED_PATTERNS:
        if pattern.search(result.normalized_log):
            matches.append(pattern.pattern)

    signal = result.canonical_signal
    score = 0.0
    if matches:
        score = max(score, 0.75)
    if signal["has_jndi"] and any(signal[key] for key in ("has_ldap", "has_rmi", "has_dns", "has_ldaps")):
        score = max(score, 0.95)
    elif signal["has_jndi"] or signal["has_lookup_syntax"]:
        score = max(score, 0.45)
    if hard_negative_context:
        score = min(score, 0.30)
    return RegexResult(label=1 if score >= 0.7 else 0, score=score, matched_patterns=matches, normalized_log=result.normalized_log)


def predict_scores(texts: list[str]) -> list[float]:
    return [predict_one(text).score for text in texts]


def predict_labels(texts: list[str], threshold: float = 0.7) -> list[int]:
    return [1 if score >= threshold else 0 for score in predict_scores(texts)]
