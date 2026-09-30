"""Timeline mode tests (ROADMAP v0.3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_diff.pipeline import PipelineOptions, PipelineResult
from fw_diff.timeline import run_timeline


class _FakeLeg:
    def __init__(self, session_id: str, high_fn: str) -> None:
        self.session_id = session_id
        self.facts = _FakeFacts(high_fn)


class _FakeFacts:
    def __init__(self, high_fn: str) -> None:
        self.summary = {
            "changed": 1,
            "added": 0,
            "removed": 0,
            "security_relevance": {"high": 1, "medium": 0, "low": 0},
        }
        self.changes = [_FakeChange(high_fn)]


class _FakeChange:
    def __init__(self, name: str) -> None:
        self.id = "CH0001"
        self.new_name = name

        from fw_diff.models import Relevance, Tag

        self.relevance = Relevance("high", {})
        self.tags = [Tag("bound_change", 0.9)]


def test_timeline_needs_two_images(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least two"):
        run_timeline([Path("a.bin")], PipelineOptions(out_dir=tmp_path))


def test_timeline_index_and_legs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_run_pipeline(old, new, opts, *, policy=None):
        calls.append((str(old), str(new)))
        return PipelineResult(
            facts=_FakeLeg(f"sess-{len(calls)}", f"fn_{len(calls)}").facts,
            policy=None,
            artifacts={},
            session_id=f"sess-{len(calls)}",
        )

    monkeypatch.setattr("fw_diff.timeline.run_pipeline", fake_run_pipeline)
    result = run_timeline(
        [Path("v1.bin"), Path("v2.bin"), Path("v3.bin")],
        PipelineOptions(out_dir=tmp_path, deterministic=True),
    )
    assert len(result.legs) == 2
    assert calls == [("v1.bin", "v2.bin"), ("v2.bin", "v3.bin")]
    assert result.index_path is not None
    index = result.index_path.read_text()
    assert "# fw-diff timeline" in index
    assert "2 high-relevance changes total" in index
    assert "| v1.bin | v2.bin |" in index
    assert "fn_1" in index and "fn_2" in index
    assert (tmp_path / "pair-01").is_dir() and (tmp_path / "pair-02").is_dir()


def test_timeline_passes_pair_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Path] = []

    def fake_run_pipeline(old, new, opts, *, policy=None):
        seen.append(opts.out_dir)
        return PipelineResult(
            facts=_FakeLeg("s", "f").facts, policy=None, artifacts={}, session_id="s"
        )

    monkeypatch.setattr("fw_diff.timeline.run_pipeline", fake_run_pipeline)
    run_timeline([Path("a"), Path("b"), Path("c"), Path("d")], PipelineOptions(out_dir=tmp_path))
    assert [p.name for p in seen] == ["pair-01", "pair-02", "pair-03"]
