"""SARIF 2.1 renderer tests."""

from __future__ import annotations

import json

import pytest

from fw_diff.models import ImageManifest
from fw_diff.pipeline import PipelineOptions, run_from_ir
from fw_diff.sarif import render_sarif


@pytest.fixture()
def doc(demo_pair, tmp_path: pytest.TempPathFactory):

    old_ir, new_ir = demo_pair
    return run_from_ir(
        old_ir,
        new_ir,
        PipelineOptions(out_dir=tmp_path / "out", deterministic=True),
        old_manifest=ImageManifest(path="demo/fw-1.4.2.bin", sha256="a"),
        new_manifest=ImageManifest(path="demo/fw-1.4.3.bin", sha256="b"),
    ).facts


def test_sarif_structure(doc) -> None:
    sarif = render_sarif(doc)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "fw-diff"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    result_rule_ids = {r["ruleId"] for r in run["results"]}
    assert result_rule_ids <= rule_ids


def test_sarif_levels_and_fingerprints(doc) -> None:
    sarif = render_sarif(doc)
    by_fp = {r["partialFingerprints"]["fwDiffChangeId"]: r for r in sarif["runs"][0]["results"]}
    # CH0002 = bound_change @ high -> warning; CH0003 = crypto @ medium -> note
    assert by_fp["CH0002"]["level"] == "warning"
    assert by_fp["CH0003"]["level"] == "note"
    assert "CH0001" not in by_fp  # low relevance excluded
    assert by_fp["CH0002"]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]


def test_sarif_written_by_pipeline(demo_pair, tmp_path: pytest.TempPathFactory) -> None:

    old_ir, new_ir = demo_pair
    result = run_from_ir(
        old_ir,
        new_ir,
        PipelineOptions(out_dir=tmp_path / "out", deterministic=True),
        old_manifest=ImageManifest(path="a", sha256="a"),
        new_manifest=ImageManifest(path="b", sha256="b"),
    )
    sarif_path = result.artifacts["sarif.json"]
    data = json.loads(sarif_path.read_text())
    assert data["runs"][0]["tool"]["driver"]["name"] == "fw-diff"
