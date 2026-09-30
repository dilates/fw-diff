"""CLI end-to-end tests (typer runner)."""

from __future__ import annotations

import json
import pathlib

import pytest
from typer.testing import CliRunner

from fw_diff import __version__
from fw_diff.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_demo_command(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["demo", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "facts.json").exists()
    assert (out / "report.md").exists()
    assert (out / "report.html").exists()
    facts = json.loads((out / "facts.json").read_text())
    assert facts["summary"]["changed"] == 5
    assert "Matched" in result.output


def test_demo_reproducible_bytes(tmp_path: pathlib.Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    assert runner.invoke(app, ["demo", "--out", str(a), "--deterministic"]).exit_code == 0
    assert runner.invoke(app, ["demo", "--out", str(b), "--deterministic"]).exit_code == 0
    # deterministic mode: byte-identical artifacts, no timestamps/uuids
    assert (a / "facts.json").read_bytes() == (b / "facts.json").read_bytes()


def test_doctor_command() -> None:
    result = runner.invoke(app, ["doctor"])
    assert "fw-diff doctor" in result.output


def test_sessions_lifecycle(tmp_path: pathlib.Path) -> None:
    from fw_diff.store import Store

    assert runner.invoke(app, ["demo", "--out", str(tmp_path / "o")]).exit_code == 0
    rows = Store().list_sessions()
    assert rows, "expected one persisted session"
    sid = rows[0]["id"]
    shown = runner.invoke(app, ["sessions", "show", sid])
    assert shown.exit_code == 0
    assert "facts" in shown.output
    assert runner.invoke(app, ["sessions", "rm", sid]).exit_code == 0
    assert Store().list_sessions() == []


def test_cache_gc_dry_run() -> None:
    result = runner.invoke(app, ["cache", "gc", "--dry-run"])
    assert result.exit_code == 0
    assert "blobs" in result.output


def test_plugins_list_empty() -> None:
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0


def test_lift_requires_ghidra(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    # tiny files so ingest succeeds; lift must fail fast without pyghidra/ghidra
    a = tmp_path / "a.c"
    a.write_text("int main(void){return 0;}\n")
    result = runner.invoke(app, ["lift", str(a), str(a), "--out", str(tmp_path)])
    assert result.exit_code == 2


def _fake_result(monkeypatch: pytest.MonkeyPatch, exit_code: int = 0) -> None:
    """Patch run_pipeline used by explain/ci commands with a canned result."""
    from fw_diff.models import FactsDoc, ImageManifest, SessionInfo
    from fw_diff.pipeline import PipelineResult
    from fw_diff.policy import PolicyDecision

    doc = FactsDoc(
        schema_version=1,
        tool_name="fw-diff",
        tool_version="0.1.0a1",
        ghidra=None,
        session=SessionInfo(
            id="s",
            created_utc=None,
            old_manifest=ImageManifest(path="o", sha256="o"),
            new_manifest=ImageManifest(path="n", sha256="n"),
            config={},
        ),
        summary={
            "functions": {"old": 1, "new": 1},
            "matches": {},
            "changed": 0,
            "added": 0,
            "removed": 0,
            "ambiguous": 0,
            "security_relevance": {"high": 0, "medium": 0, "low": 0},
        },
        changes=[],
        added=[],
        removed=[],
        ambiguous=[],
        lift_gaps=[],
    )
    decision = (
        PolicyDecision()
        if exit_code == 0
        else PolicyDecision(failures=[{"rule": {"classifier": "x"}, "change_ids": ["CH0001"]}])
    )
    result = PipelineResult(facts=doc, policy=decision, artifacts={}, session_id="s")
    monkeypatch.setattr("fw_diff.cli.run_pipeline", lambda *a, **k: result)


def test_ci_command_pass(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on: []\n")
    _fake_result(monkeypatch, exit_code=0)
    result = runner.invoke(app, ["ci", "a.bin", "b.bin", "--policy", str(policy)])
    assert result.exit_code == 0, result.output
    assert '"failures": []' in result.output


def test_ci_command_policy_fail(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on: [crypto_constant_change]\n")
    _fake_result(monkeypatch, exit_code=1)
    result = runner.invoke(app, ["ci", "a.bin", "b.bin", "--policy", str(policy)])
    assert result.exit_code == 1


def test_ci_command_ingest_error(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fw_diff.ingest import IngestError

    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on: []\n")
    monkeypatch.setattr(
        "fw_diff.cli.run_pipeline", lambda *a, **k: (_ for _ in ()).throw(IngestError("bad image"))
    )
    result = runner.invoke(app, ["ci", "a.bin", "b.bin", "--policy", str(policy)])
    assert result.exit_code == 2
    assert "bad image" in result.output


def test_explain_command(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    _fake_result(monkeypatch)
    result = runner.invoke(app, ["explain", "a.bin", "b.bin", "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Matched" in result.output


def test_explain_command_ingest_error(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fw_diff.pipeline import PipelineError

    monkeypatch.setattr(
        "fw_diff.cli.run_pipeline", lambda *a, **k: (_ for _ in ()).throw(PipelineError("boom"))
    )
    result = runner.invoke(app, ["explain", "a.bin", "b.bin", "--out", str(tmp_path)])
    assert result.exit_code == 2


def test_sessions_show_missing() -> None:
    result = runner.invoke(app, ["sessions", "show", "nope"])
    assert result.exit_code == 2


def test_sessions_rm_missing() -> None:
    result = runner.invoke(app, ["sessions", "rm", "nope"])
    assert result.exit_code == 2


def test_cache_gc_real_run() -> None:
    result = runner.invoke(app, ["cache", "gc"])
    assert result.exit_code == 0
    assert "removed" in result.output


def test_load_policy_invalid_yaml(tmp_path: pathlib.Path) -> None:
    policy = tmp_path / "bad.yaml"
    policy.write_text("- just a list\n")  # not a mapping -> PolicyError -> exit 2
    result = runner.invoke(app, ["ci", "a", "b", "--policy", str(policy)])
    assert result.exit_code == 2
    assert "policy error" in result.output
