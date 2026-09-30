"""S3 embedding stage tests: fake provider semantics + optional real fastembed."""

from __future__ import annotations

import pytest

from fw_diff.demo import load_demo_ir
from fw_diff.embed import FastEmbedProvider, make_embedder
from fw_diff.facts import assign_ids
from fw_diff.match import STAGE_EMBED, EmbeddingProvider, run_match


class ScalarEmbedder(EmbeddingProvider):
    """Deterministic toy embedder: vector keyed by token hash — no external model."""

    name = "scalar-test"

    def embed(self, texts: list[str]) -> list[list[float]]:
        vecs = []
        for text in texts:
            v = [0.0] * 16
            for tok in text.split():
                v[hash(tok) % 16] += 1.0
            vecs.append(v)
        return vecs


def test_s3_runs_when_provider_given() -> None:
    old_ir, new_ir = load_demo_ir()
    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))
    result, _, _ = run_match(old_ir, new_ir, embedder=ScalarEmbedder())
    assert STAGE_EMBED not in result.skipped_stages


def test_s3_skipped_without_provider(demo_matched) -> None:
    _, _, result, _, _ = demo_matched
    assert "embedding" in result.skipped_stages


def test_margin_rule_rejects_ambiguous() -> None:
    """Two near-identical old functions vs one new: margin rule must reject, not guess."""
    from fw_diff.models import FunctionIR

    body = "int f(void)\n{\n  return 1;\n}"
    old_ir = [
        FunctionIR(
            id="F0001",
            image="old",
            name="FUN_100",
            addr=0x100,
            pseudocode_raw="int f(void)\n{\n  return 1;\n}",
        ),
        FunctionIR(
            id="F0002",
            image="old",
            name="FUN_200",
            addr=0x200,
            pseudocode_raw="int g(void)\n{\n  return 1;\n}",
        ),
    ]
    new_ir = [
        FunctionIR(
            id="F0003",
            image="new",
            name="FUN_300",
            addr=0x300,
            pseudocode_raw="int h(void)\n{\n  return 1;\n}",
        ),
    ]
    # identical struct hashes -> the embedder sees both candidates at sim 1.0; margin 0
    _ = body
    result, _, _ = run_match(old_ir, new_ir, embedder=ScalarEmbedder())
    # the pair must NOT be confidently matched to either candidate by S3
    s3_pairs = [p for p in result.pairs if p.method == STAGE_EMBED]
    assert not s3_pairs or result.ambiguous


def test_make_embedder_disabled_returns_none() -> None:
    assert make_embedder(False) is None


def test_make_embedder_without_fastembed_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def _no_fastembed(name: str, *args: object, **kwargs: object):
        if name == "fastembed":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _no_fastembed)
    assert make_embedder(True) is None


def test_fastembed_error_message() -> None:
    import fw_diff.embed as embed_mod

    try:
        FastEmbedProvider()
        has_fastembed = True
    except RuntimeError as exc:
        assert "'fw-diff[embed]'" in str(exc)
        has_fastembed = False
    _ = embed_mod
    if has_fastembed:  # installed locally: sanity-check it embeds
        provider = FastEmbedProvider()
        vecs = provider.embed(["return 1;", "memcpy(dst, src, 0x40);"])
        assert len(vecs) == 2 and all(len(v) > 16 for v in vecs)
