"""Character-level feature builders for Log4Shell detection."""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np

from .canonicalizer import canonicalize
from .paths import MODELS_DIR


PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
DEFAULT_MAX_LEN = 512
SIGNAL_KEYS = [
    "has_jndi",
    "has_ldap",
    "has_rmi",
    "has_dns",
    "has_ldaps",
    "has_lookup_syntax",
    "has_nested_lookup",
    "has_url_encoding",
    "has_html_entity",
    "has_unicode_escape",
    "has_lower_upper_lookup",
    "has_env_fallback",
    "has_fragmented_jndi",
]


@dataclass
class CharTokenizer:
    vocab: dict[str, int]
    max_len: int = DEFAULT_MAX_LEN

    @classmethod
    def fit(cls, texts: Iterable[str], max_len: int = DEFAULT_MAX_LEN) -> "CharTokenizer":
        chars: set[str] = set()
        for text in texts:
            chars.update(str(text))
        vocab = {PAD_TOKEN: 0, UNK_TOKEN: 1}
        for idx, char in enumerate(sorted(chars), start=2):
            vocab[char] = idx
        return cls(vocab=vocab, max_len=max_len)

    @property
    def vocab_size(self) -> int:
        return len(self.vocab)

    def encode_one(self, text: str) -> np.ndarray:
        sequence = [self.vocab.get(char, self.vocab[UNK_TOKEN]) for char in str(text)[: self.max_len]]
        sequence.extend([self.vocab[PAD_TOKEN]] * (self.max_len - len(sequence)))
        return np.asarray(sequence, dtype=np.int32)

    def encode_many(self, texts: Iterable[str]) -> np.ndarray:
        return np.vstack([self.encode_one(text) for text in texts])

    def save(self, path: str | Path = MODELS_DIR / "tokenizer.pkl") -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            pickle.dump({"vocab": self.vocab, "max_len": self.max_len}, handle)

    @classmethod
    def load(cls, path: str | Path = MODELS_DIR / "tokenizer.pkl") -> "CharTokenizer":
        with Path(path).open("rb") as handle:
            payload = pickle.load(handle)
        return cls(vocab=payload["vocab"], max_len=int(payload["max_len"]))


def signal_vector(text: str) -> np.ndarray:
    result = canonicalize(text)
    return np.asarray([1.0 if result.canonical_signal.get(key, False) else 0.0 for key in SIGNAL_KEYS], dtype=np.float32)


def signal_matrix(texts: Iterable[str]) -> np.ndarray:
    return np.vstack([signal_vector(text) for text in texts])
