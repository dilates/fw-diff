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
