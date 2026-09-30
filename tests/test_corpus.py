"""Corpus cases in IR-fixture mode (testing-strategy §3): expect.json vs demo IR pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fw_diff.demo import load_demo_ir
from fw_diff.facts import assign_ids
from fw_diff.models import ImageManifest
from fw_diff.pipeline import PipelineOptions, run_from_ir

CORPUS = Path(__file__).parent / "corpus"
# the committed demo IR pair is the lifted IR of the bounds-fix case (see corpus README)
CASE_TO_FIXTURE = {"bounds-fix": ("demo/fw-1.4.2.bin", "demo/fw-1.4.3.bin")}


def _run_case(case: str, tmp_path: Path):
    old_ir, new_ir = load_demo_ir()
    assign_ids(old_ir)
    assign_ids(new_ir)
    old_name, new_name = CASE_TO_FIXTURE[case]
    return run_from_ir(
        old_ir,
        new_ir,
        PipelineOptions(out_dir=tmp_path / "out", deterministic=True),
        old_manifest=ImageManifest(path=old_name, sha256="corpus-old"),
        new_manifest=ImageManifest(path=new_name, sha256="corpus-new"),
    ).facts


@pytest.mark.corpus
@pytest.mark.parametrize("case", sorted(p.name for p in CORPUS.iterdir() if p.is_dir()))
def test_corpus_expectations(case: str, tmp_path: Path) -> None:
    if case not in CASE_TO_FIXTURE:
        pytest.skip(f"no IR fixture for {case} yet (full mode only — see corpus README)")
    expect = json.loads((CORPUS / case / "expect.json").read_text())
    doc = _run_case(case, tmp_path)

    for rule in expect.get("must_tag", []):
        tag = rule["classifier"]
        fn_name = rule["function"]
        hits = [c for c in doc.changes if tag in {t.tag for t in c.tags} and fn_name == c.new_name]
        assert hits, (
            f"{case}: expected {tag} on {fn_name}, got "
            f"{[(c.new_name, [t.tag for t in c.tags]) for c in doc.changes]}"
        )
        if "relevance" in rule:
            assert hits[0].relevance.score == rule["relevance"]

    for rule in expect.get("must_not_tag", []):
        tag = rule["classifier"]
        fn_name = rule["function"]
        offenders = [
            c.id for c in doc.changes if tag in {t.tag for t in c.tags} and fn_name == c.new_name
        ]
        assert not offenders, f"{case}: unexpected {tag} on {fn_name}: {offenders}"

    for key in expect.get("summary", {}):
        assert doc.summary[key] == expect["summary"][key]
