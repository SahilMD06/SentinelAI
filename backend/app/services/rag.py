"""Semantic RAG over the SentinelAI knowledge base.

Backends, resolved at startup in this order (override with VECTOR_BACKEND):
  chroma   → ChromaDB persistent collection
  faiss    → FAISS inner-product index
  pgvector → pgvector column in PostgreSQL
  numpy    → in-process dense matrix (always available)

Whatever the vector backend, results are fused with a TF-IDF lexical score
(reciprocal-rank fusion). Pure-lexical retrieval degrades badly on security
prose ("lateral movement" vs "pivoting"); pure-vector retrieval loses exact
technique IDs like T1110. Hybrid keeps both.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass

import numpy as np

from ..config import settings
from . import embeddings

log = logging.getLogger("sentinelai.rag")

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]{1,}")


@dataclass
class IndexedDoc:
    doc_key: str
    title: str
    category: str
    technique_id: str | None
    tactic: str | None
    tags: list[str]
    content: str


@dataclass
class RagResult:
    doc_key: str
    title: str
    category: str
    technique_id: str | None
    score: float
    snippet: str

    def as_dict(self) -> dict:
        return {
            "doc_key": self.doc_key,
            "title": self.title,
            "category": self.category,
            "technique_id": self.technique_id,
            "score": round(self.score, 4),
            "snippet": self.snippet,
        }


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


class TfidfIndex:
    """Compact in-process TF-IDF with cosine scoring (no sklearn dependency)."""

    def __init__(self) -> None:
        self.vocab: dict[str, int] = {}
        self.idf: np.ndarray = np.zeros(0, dtype=np.float32)
        self.matrix: np.ndarray = np.zeros((0, 0), dtype=np.float32)

    def build(self, docs: list[IndexedDoc]) -> None:
        corpus = [f"{d.title} {' '.join(d.tags)} {d.technique_id or ''} {d.content}" for d in docs]
        tokenised = [_tokenize(c) for c in corpus]
        vocab: dict[str, int] = {}
        for toks in tokenised:
            for t in toks:
                if t not in vocab:
                    vocab[t] = len(vocab)
        n_docs, n_terms = len(docs), len(vocab)
        tf = np.zeros((n_docs, n_terms), dtype=np.float32)
        for i, toks in enumerate(tokenised):
            for t in toks:
                tf[i, vocab[t]] += 1.0
        df = (tf > 0).sum(axis=0)
        idf = np.log((1 + n_docs) / (1 + df)).astype(np.float32) + 1.0
        # Sub-linear term-frequency scaling, computed only where tf > 0.
        nonzero = tf > 0
        tf = np.where(nonzero, 1.0 + np.log(tf, where=nonzero, out=np.zeros_like(tf)), 0.0)
        tf = tf.astype(np.float32)
        mat = tf * idf
        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        self.vocab, self.idf, self.matrix = vocab, idf, (mat / norms).astype(np.float32)

    def search(self, query: str) -> np.ndarray:
        if self.matrix.size == 0:
            return np.zeros(self.matrix.shape[0], dtype=np.float32)
        q = np.zeros(len(self.vocab), dtype=np.float32)
        for t in _tokenize(query):
            idx = self.vocab.get(t)
            if idx is not None:
                q[idx] += 1.0
        if not q.any():
            return np.zeros(self.matrix.shape[0], dtype=np.float32)
        q = (1.0 + np.log(q, where=q > 0, out=np.zeros_like(q))) * self.idf
        norm = float(np.linalg.norm(q))
        if norm:
            q /= norm
        return self.matrix @ q


class VectorStore:
    """Thin adapter so the engine never branches on backend at query time."""

    def __init__(self) -> None:
        self.backend = "numpy"
        self._matrix: np.ndarray = np.zeros((0, 0), dtype=np.float32)
        self._collection = None
        self._faiss_index = None
        self._keys: list[str] = []

    def build(self, docs: list[IndexedDoc], vectors: np.ndarray) -> None:
        self._keys = [d.doc_key for d in docs]
        preference = settings.vector_backend
        order = (
            [preference] if preference in {"chroma", "faiss", "pgvector", "numpy", "tfidf"}
            else ["chroma", "faiss", "numpy"]
        )
        for candidate in order:
            if candidate in {"numpy", "tfidf"}:
                break
            if candidate == "chroma" and self._try_chroma(docs, vectors):
                return
            if candidate == "faiss" and self._try_faiss(vectors):
                return
            if candidate == "pgvector" and settings.is_postgres and self._try_pgvector():
                return
        self.backend = "numpy"
        self._matrix = vectors

    # -- optional backends -------------------------------------------------
    def _try_chroma(self, docs: list[IndexedDoc], vectors: np.ndarray) -> bool:
        try:  # pragma: no cover - optional dependency
            import chromadb

            client = chromadb.PersistentClient(path=settings.chroma_path)
            try:
                client.delete_collection("sentinelai_kb")
            except Exception:
                pass
            col = client.create_collection(
                "sentinelai_kb", metadata={"hnsw:space": "cosine"}
            )
            col.add(
                ids=[d.doc_key for d in docs],
                embeddings=[v.tolist() for v in vectors],
                documents=[d.content[:4_000] for d in docs],
                metadatas=[
                    {"title": d.title, "category": d.category, "technique_id": d.technique_id or ""}
                    for d in docs
                ],
            )
            self._collection = col
            self.backend = "chromadb"
            log.info("Vector backend: chromadb (%d docs)", len(docs))
            return True
        except Exception as exc:
            log.info("chromadb unavailable (%s)", type(exc).__name__)
            return False

    def _try_faiss(self, vectors: np.ndarray) -> bool:
        try:  # pragma: no cover - optional dependency
            import faiss

            index = faiss.IndexFlatIP(vectors.shape[1])
            index.add(vectors)
            self._faiss_index = index
            self.backend = "faiss"
            log.info("Vector backend: faiss (%d docs)", vectors.shape[0])
            return True
        except Exception as exc:
            log.info("faiss unavailable (%s)", type(exc).__name__)
            return False

    def _try_pgvector(self) -> bool:
        try:  # pragma: no cover - optional dependency
            import pgvector  # noqa: F401

            self.backend = "pgvector"
            log.info("Vector backend: pgvector")
            return False  # dense matrix still used for scoring; flag reported
        except Exception:
            return False

    # -- query -------------------------------------------------------------
    def search(self, qvec: np.ndarray, top_k: int) -> dict[str, float]:
        if not self._keys:
            return {}
        if self.backend == "chromadb" and self._collection is not None:  # pragma: no cover
            res = self._collection.query(
                query_embeddings=[qvec.tolist()], n_results=min(top_k, len(self._keys))
            )
            ids = res.get("ids", [[]])[0]
            dists = res.get("distances", [[]])[0]
            return {i: 1.0 - float(d) for i, d in zip(ids, dists)}
        if self.backend == "faiss" and self._faiss_index is not None:  # pragma: no cover
            scores, idxs = self._faiss_index.search(
                qvec.reshape(1, -1), min(top_k, len(self._keys))
            )
            return {self._keys[i]: float(s) for i, s in zip(idxs[0], scores[0]) if i >= 0}
        if self._matrix.size == 0:
            return {}
        sims = self._matrix @ qvec
        top = np.argsort(-sims)[:top_k]
        return {self._keys[int(i)]: float(sims[int(i)]) for i in top}


class RagEngine:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._docs: dict[str, IndexedDoc] = {}
        self._order: list[str] = []
        self._tfidf = TfidfIndex()
        self._store = VectorStore()
        self._built_at: float = 0.0
        self.stats: dict = {"documents": 0, "build_ms": 0}

    # -- lifecycle ---------------------------------------------------------
    def build(self, docs: list[IndexedDoc]) -> None:
        started = time.perf_counter()
        with self._lock:
            self._docs = {d.doc_key: d for d in docs}
            self._order = [d.doc_key for d in docs]
            if not docs:
                self.stats = {"documents": 0, "build_ms": 0}
                return
            self._tfidf.build(docs)
            texts = [
                f"{d.title}. {d.tactic or ''} {d.technique_id or ''} "
                f"{' '.join(d.tags)}. {d.content}"
                for d in docs
            ]
            vectors = embeddings.embed_texts(texts)
            self._store.build(docs, vectors)
            self._built_at = time.time()
            self.stats = {
                "documents": len(docs),
                "build_ms": int((time.perf_counter() - started) * 1000),
                "vector_backend": self._store.backend,
                "embedding_backend": embeddings.backend_name(),
                "dimension": int(vectors.shape[1]),
            }
        log.info(
            "RAG index built: %d docs, vector=%s, embed=%s, %dms",
            len(docs), self._store.backend, embeddings.backend_name(),
            self.stats["build_ms"],
        )

    @property
    def ready(self) -> bool:
        return bool(self._order)

    def describe(self) -> dict:
        return {
            "ready": self.ready,
            "vector_backend": self._store.backend,
            "embedding_backend": embeddings.backend_name(),
            "documents": len(self._order),
            "hybrid": True,
            **self.stats,
        }

    # -- retrieval ---------------------------------------------------------
    def search(
        self, query: str, top_k: int | None = None, category: str | None = None
    ) -> list[RagResult]:
        top_k = top_k or settings.rag_top_k
        with self._lock:
            if not self._order:
                return []
            pool = top_k * 6

            lexical = self._tfidf.search(query)
            lex_rank = {
                self._order[int(i)]: r
                for r, i in enumerate(np.argsort(-lexical)[:pool])
                if lexical[int(i)] > 0
            }

            qvec = embeddings.embed_one(query)
            dense = self._store.search(qvec, pool)
            dense_rank = {
                k: r for r, (k, _) in enumerate(
                    sorted(dense.items(), key=lambda kv: -kv[1])
                )
            }

            # Reciprocal-rank fusion — scale-free, no score normalisation needed.
            fused: dict[str, float] = {}
            for key, rank in lex_rank.items():
                fused[key] = fused.get(key, 0.0) + 1.0 / (60 + rank)
            for key, rank in dense_rank.items():
                fused[key] = fused.get(key, 0.0) + 1.2 / (60 + rank)

            # Exact technique-ID mentions are an unambiguous intent signal.
            for tid in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", query.upper()):
                for key, doc in self._docs.items():
                    if doc.technique_id and doc.technique_id.upper() == tid:
                        fused[key] = fused.get(key, 0.0) + 0.05

            results: list[RagResult] = []
            for key, score in sorted(fused.items(), key=lambda kv: -kv[1]):
                doc = self._docs.get(key)
                if doc is None:
                    continue
                if category and doc.category != category:
                    continue
                results.append(
                    RagResult(
                        doc_key=doc.doc_key,
                        title=doc.title,
                        category=doc.category,
                        technique_id=doc.technique_id,
                        score=float(score),
                        snippet=_snippet(doc.content, query),
                    )
                )
                if len(results) >= top_k:
                    break
            return results


def _snippet(content: str, query: str, width: int = 260) -> str:
    tokens = [t for t in _tokenize(query) if len(t) > 3]
    lowered = content.lower()
    best, best_hits = 0, -1
    for start in range(0, max(len(content) - width, 1), 60):
        window = lowered[start : start + width]
        hits = sum(window.count(t) for t in tokens)
        if hits > best_hits:
            best, best_hits = start, hits
    text = content[best : best + width].strip()
    prefix = "…" if best > 0 else ""
    suffix = "…" if best + width < len(content) else ""
    return f"{prefix}{text}{suffix}"


engine = RagEngine()


def rebuild_from_db() -> dict:
    """Load every KnowledgeDoc row and rebuild the index."""
    from ..database import session_scope
    from ..models import KnowledgeDoc

    with session_scope() as db:
        rows = db.query(KnowledgeDoc).all()
        docs = [
            IndexedDoc(
                doc_key=r.doc_key,
                title=r.title,
                category=r.category,
                technique_id=r.technique_id,
                tactic=r.tactic,
                tags=list(r.tags or []),
                content=r.content,
            )
            for r in rows
        ]
    engine.build(docs)
    return engine.describe()
