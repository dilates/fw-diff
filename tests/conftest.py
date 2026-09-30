"""Shared fixtures: demo IR pair + isolated cache."""

from __future__ import annotations

import pytest

from fw_diff.demo import load_demo_ir
from fw_diff.facts import assign_ids
from fw_diff.match import run_match


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory):
    """Keep every test's session store inside a throwaway cache dir."""
    cache = tmp_path / "fw-diff-cache"  # type: ignore[attr-defined]
    monkeypatch.setenv("FW_DIFF_CACHE", str(cache))
    yield


@pytest.fixture()
def demo_pair():
    """Fresh demo IR pair with ids assigned (deep copies per test)."""
    old_ir, new_ir = load_demo_ir()
    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))  # session-unique ids (report-format convention)
    return old_ir, new_ir


@pytest.fixture()
def demo_matched(demo_pair):
    old_ir, new_ir = demo_pair
    result, old_norm, new_norm = run_match(old_ir, new_ir)
    return old_ir, new_ir, result, old_norm, new_norm
