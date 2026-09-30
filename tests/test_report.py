"""Report renderer tests (single-file offline HTML, ADR-0010)."""

from __future__ import annotations

import pytest

from fw_diff.pipeline import PipelineOptions, run_from_ir
from fw_diff.render import render_html, render_markdown


@pytest.fixture()
def doc(demo_pair, tmp_path: pytest.TempPathFactory):
    from fw_diff.models import ImageManifest

    old_ir, new_ir = demo_pair
    opts = PipelineOptions(out_dir=tmp_path / "out", deterministic=True)  # type: ignore[arg-type]
    return run_from_ir(
        old_ir,
        new_ir,
        opts,
        old_manifest=ImageManifest(path="demo/fw-1.4.2.bin", sha256="a"),
        new_manifest=ImageManifest(path="demo/fw-1.4.3.bin", sha256="b"),
    ).facts


def test_markdown_structure(doc) -> None:
    md = render_markdown(doc)
    assert md.startswith("# fw-diff: demo/fw-1.4.2.bin → demo/fw-1.4.3.bin")
    assert "**Matched 7/8**" in md
    assert "## High-relevance changes (1)" in md
    assert "CH0002" in md and "CWE-190" in md
    assert "`+ if ( 0x40 < l1 ) {`" in md
    assert "## Appendix" in md


def test_markdown_deterministic_session_has_no_timestamp(doc) -> None:
    md = render_markdown(doc)
    assert "deterministic session" in md


def test_html_no_external_urls(doc) -> None:
    page = render_html(doc)
    assert "<!doctype html>" in page
    assert "http://" not in page and "https://" not in page  # offline rule (ADR-0010)
    assert "CH0002" in page and "bound_change" in page


def test_html_escapes_snippets(doc) -> None:
    doc.changes[0].edits[0].new_snippet = '<script>alert("x")</script>'
    page = render_html(doc)
    # the only <script> allowed is fw-diff's own filter JS; injected code must be escaped
    assert 'alert("x")' not in page
    assert "&lt;script&gt;" in page
    assert page.count("<script>") == 1


def test_llm_provenance_visible_when_explain_present(doc) -> None:
    from fw_diff.models import ExplainBlock

    doc.changes[0].explain = ExplainBlock(
        narrative="Model text.",
        confidence="low",
        claims=[],
        provenance={"model": "llama3.1:8b", "prompt_version": "pv1", "dropped_claims": 0},
    )
    page = render_html(doc)
    assert "llama3.1:8b" in page
    assert "prompt_version" in page or "pv1" in page
