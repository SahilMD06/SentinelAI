"""Embedding provider with a deterministic offline fallback.

Priority order:
  1. sentence-transformers (`all-MiniLM-L6-v2` by default) when installed.
  2. OpenAI `text-embedding-3-small` when OPENAI_API_KEY is present.
  3. Hashed n-gram projection — deterministic, dependency-free, and good enough
     for cosine ranking over a security corpus of a few hundred documents.

The fallback keeps identical call signatures so nothing downstream branches.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import threading

import numpy as np

from ..config import settings

log = logging.getLogger("sentinelai.embeddings")

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]{1,}")
_lock = threading.Lock()
_model = None
_backend = "hashing"
_probed = False


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def _probe() -> None:
    """Lazily resolve the best available embedding backend, once."""
    global _model, _backend, _probed
    if _probed:
        return
    with _lock:
        if _probed:
            return
        _probed = True
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore

            _model = SentenceTransformer(settings.embedding_model)
            _backend = f"sentence-transformers:{settings.embedding_model}"
            log.info("Embeddings via %s", _backend)
            return
        except Exception as exc:  # pragma: no cover - optional dependency
            log.info("sentence-transformers unavailable (%s)", type(exc).__name__)

        if os.getenv("OPENAI_API_KEY"):
            try:
                from openai import OpenAI  # type: ignore

                _model = OpenAI()
                _backend = "openai:text-embedding-3-small"
                log.info("Embeddings via %s", _backend)
                return
            except Exception as exc:  # pragma: no cover - optional dependency
                log.info("openai client unavailable (%s)", type(exc).__name__)

        _backend = "hashing-ngram"
        log.info("Embeddings via deterministic %s fallback", _backend)


def backend_name() -> str:
    _probe()
    return _backend


def dimension() -> int:
    _probe()
    if _backend.startswith("sentence-transformers"):
        try:
            return int(_model.get_sentence_embedding_dimension())  # type: ignore[union-attr]
        except Exception:  # pragma: no cover
            return settings.embedding_dim
    if _backend.startswith("openai"):
        return 1536
    return settings.embedding_dim


def _hash_embed_one(text: str, dim: int) -> np.ndarray:
    vec = np.zeros(dim, dtype=np.float32)
    tokens = _tokenize(text)
    if not tokens:
        return vec
    grams = tokens + [f"{a}_{b}" for a, b in zip(tokens, tokens[1:])]
    # sub-linear term weighting keeps common words from dominating
    counts: dict[str, int] = {}
    for g in grams:
        counts[g] = counts.get(g, 0) + 1
    for gram, count in counts.items():
        digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(digest[:4], "big") % dim
        sign = 1.0 if digest[4] & 1 else -1.0
        vec[idx] += sign * (1.0 + math.log(count))
    norm = float(np.linalg.norm(vec))
    return vec / norm if norm else vec


def embed_texts(texts: list[str]) -> np.ndarray:
    """Returns an L2-normalised (n, dim) float32 matrix."""
    _probe()
    if not texts:
        return np.zeros((0, dimension()), dtype=np.float32)

    if _backend.startswith("sentence-transformers"):
        try:  # pragma: no cover - optional dependency
            arr = _model.encode(  # type: ignore[union-attr]
                texts, normalize_embeddings=True, show_progress_bar=False,
                batch_size=32, convert_to_numpy=True,
            )
            return np.asarray(arr, dtype=np.float32)
        except Exception as exc:
            log.warning("sentence-transformers encode failed, falling back: %s", exc)

    if _backend.startswith("openai"):
        try:  # pragma: no cover - optional dependency
            out = _model.embeddings.create(  # type: ignore[union-attr]
                model="text-embedding-3-small", input=texts
            )
            arr = np.asarray([d.embedding for d in out.data], dtype=np.float32)
            norms = np.linalg.norm(arr, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            return arr / norms
        except Exception as exc:
            log.warning("OpenAI embeddings failed, falling back: %s", exc)

    dim = settings.embedding_dim
    return np.vstack([_hash_embed_one(t, dim) for t in texts]).astype(np.float32)


def embed_one(text: str) -> np.ndarray:
    return embed_texts([text])[0]
