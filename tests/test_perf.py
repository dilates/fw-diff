"""Perf smoke (ROADMAP v0.2 budget tracking): fixture pipeline duration bound.

The real 16 MB pair budget (ARCHITECTURE §7) is tracked locally/at release with real
firmware; this CI-safe test pins the fixture path so gross regressions surface in CI.
"""

from __future__ import annotations

import time

import pytest

from fw_diff.demo import load_demo_ir
from fw_diff.models import ImageManifest
from fw_diff.pipeline import PipelineOptions, run_from_ir

pytestmark = pytest.mark.perf


def test_fixture_pipeline_under_bound(tmp_path: pytest.TempPathFactory) -> None:
    old_ir, new_ir = load_demo_ir()
    opts = PipelineOptions(out_dir=tmp_path / "out", deterministic=True)  # type: ignore[arg-type]
    start = time.monotonic()
    run_from_ir(
        old_ir,
        new_ir,
        opts,
        old_manifest=ImageManifest(path="perf-old", sha256="a"),
        new_manifest=ImageManifest(path="perf-new", sha256="b"),
    )
    elapsed = time.monotonic() - start
    assert elapsed < 10.0, f"fixture pipeline regressed: {elapsed:.1f}s (bound 10s)"
