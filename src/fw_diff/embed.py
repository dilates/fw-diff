"""S3 embedding provider (pipeline-spec §4, ROADMAP v0.2/M3).

Optional: requires the ``embed`` extra (fastembed + ONNX runtime). The model name is
recorded in facts config when the stage runs; matching stays deterministic per model
version because the ambiguity margin rule (§4) bounds what embeddings may decide.
"""

from __future__ import annotations

from typing import Any

from .log import get_logger
from .match import EmbeddingProvider

log = get_logger("fw_diff.embed")

DEFAULT_MODEL = "BAAI/bge-small-en-v1.5"


class FastEmbedProvider(EmbeddingProvider):
    """Cosine-capable embeddings via fastembed; model cached under the fw-diff cache."""

    def __init__(self, model_name: str = DEFAULT_MODEL, cache_dir: Any = None) -> None:
        try:
            from fastembed import TextEmbedding
        except ImportError as exc:
            raise RuntimeError("fastembed is not installed: pip install 'fw-diff[embed]'") from exc
        self.name = f"fastembed/{model_name}"
        self._model = TextEmbedding(model_name=model_name, cache_dir=cache_dir)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = [[float(x) for x in vec] for vec in self._model.embed(texts)]
        if len(vectors) != len(texts):  # pragma: no cover - fastembed contract
            raise RuntimeError(f"fastembed returned {len(vectors)} vectors for {len(texts)} texts")
        return vectors


def make_embedder(enabled: bool) -> EmbeddingProvider | None:
    """Return a provider when enabled and importable; None otherwise (stage skipped)."""
    if not enabled:
        return None
    try:
        return FastEmbedProvider()
    except RuntimeError as exc:
        log.warning("embedding unavailable; S3 stage will be skipped", extra={"count": 1})
        log.debug(str(exc))
        return None
