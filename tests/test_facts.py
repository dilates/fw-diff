"""Facts document, reproducibility, and schema tests (report-format v1)."""

from __future__ import annotations

import json

import pytest

from fw_diff.demo import load_demo_ir
from fw_diff.facts import assign_ids, deterministic_session_id
from fw_diff.models import ImageManifest
from fw_diff.pipeline import PipelineOptions, run_from_ir
from fw_diff.policy import evaluate_policy


def _manifest(name: str) -> ImageManifest:
    return ImageManifest(path=f"demo/{name}.bin", sha256="deadbeef" * 8)


def _full_facts(tmp_path: pytest.TempPathFactory):
    old_ir, new_ir = load_demo_ir()
    opts = PipelineOptions(out_dir=tmp_path / "out", deterministic=True)  # type: ignore[arg-type]
    return run_from_ir(
        old_ir, new_ir, opts, old_manifest=_manifest("fw-1.4.2"), new_manifest=_manifest("fw-1.4.3")
    )


def test_facts_schema_keys(tmp_path: pytest.TempPathFactory) -> None:
    doc = _full_facts(tmp_path).facts
    d = json.loads(doc.to_json())
    assert d["schema_version"] == 1
    assert set(d["tool"]) == {"name", "version", "ghidra"}
    assert set(d["session"]) == {"id", "created_utc", "old", "new", "config"}
    assert set(d["summary"]) >= {
        "functions",
        "matches",
        "changed",
        "added",
        "removed",
        "ambiguous",
        "security_relevance",
    }
    change = d["changes"][0]
    assert set(change) >= {
        "id",
        "pair",
        "names",
        "match",
        "edits",
        "classifiers",
        "security_relevance",
        "hypotheses",
    }


def test_deterministic_reproducibility(tmp_path: pytest.TempPathFactory) -> None:
    r1 = _full_facts(tmp_path)
    r2 = _full_facts(tmp_path)
    j1 = r1.facts.to_json()
    j2 = r2.facts.to_json()
    assert j1 == j2  # byte-identical
    # written artifact matches in-memory serialization
    written = (tmp_path / "out" / "facts.json").read_text()  # type: ignore[attr-defined]
    assert written == j1


def test_deterministic_session_id_stable(tmp_path: pytest.TempPathFactory) -> None:
    r1 = _full_facts(tmp_path)
    r2 = _full_facts(tmp_path)
    assert r1.facts.session.id == r2.facts.session.id
    assert r1.facts.session.created_utc is None
    assert deterministic_session_id("a", "b") == deterministic_session_id("a", "b")


def test_non_deterministic_session_has_uuid_and_time(tmp_path: pytest.TempPathFactory) -> None:
    old_ir, new_ir = load_demo_ir()
    opts = PipelineOptions(out_dir=tmp_path / "out", deterministic=False)  # type: ignore[arg-type]
    doc = run_from_ir(
        old_ir, new_ir, opts, old_manifest=_manifest("a"), new_manifest=_manifest("b")
    ).facts
    assert doc.session.created_utc is not None
    assert len(doc.session.id) == 16


def test_summary_counts_consistent(tmp_path: pytest.TempPathFactory) -> None:
    doc = _full_facts(tmp_path).facts
    s = doc.summary
    assert s["functions"] == {"old": 8, "new": 8}
    assert s["changed"] == len(doc.changes) == 5
    assert s["added"] == len(doc.added) == 1
    assert s["removed"] == len(doc.removed) == 1
    assert sum(s["security_relevance"].values()) == 5
    matched = sum(s["matches"].values())
    assert matched + s["added"] == s["functions"]["new"]


def test_removed_entry_carries_auth_surface(tmp_path: pytest.TempPathFactory) -> None:
    doc = _full_facts(tmp_path).facts
    removed = {r["name"]: r for r in doc.removed}
    assert removed["FUN_4001aa00"]["auth_surface"] is True
    assert removed["FUN_4001aa00"]["called_by"] == ["F0005"]


def test_policy_evaluates_against_facts(tmp_path: pytest.TempPathFactory) -> None:
    doc = _full_facts(tmp_path).facts
    decision = evaluate_policy(
        doc,
        {
            "fail_on": [{"classifier": "bound_change", "where": "security_relevance == high"}],
            "warn_on": ["string_change"],
        },
    )
    assert decision.exit_code == 1
    assert decision.failures[0]["change_ids"] == ["CH0002"]
    assert decision.warnings


def test_policy_passes_clean_ruleset(tmp_path: pytest.TempPathFactory) -> None:
    doc = _full_facts(tmp_path).facts
    decision = evaluate_policy(
        doc,
        {
            "fail_on": [
                {"classifier": "crypto_constant_change", "where": "security_relevance == high"}
            ]
        },
    )
    assert decision.exit_code == 0
    assert not decision.failures


def test_assign_ids_ordered_by_address() -> None:
    ir = load_demo_ir()[0]
    assign_ids(ir)
    addrs = [fn.addr for fn in ir]
    assert addrs == sorted(addrs)
    assert [fn.id for fn in ir] == [f"F{i:04d}" for i in range(1, len(ir) + 1)]
