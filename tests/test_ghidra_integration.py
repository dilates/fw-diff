"""Ghidra integration tests — run with: pytest -m ghidra.

Requires pyghidra + a local Ghidra 11.3+ (GHIDRA_INSTALL_DIR or ~/re/ghidra_*).
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("pyghidra", reason="pyghidra not installed (pip install '.[ghidra]')")


def _ghidra_dir() -> Path | None:
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and Path(env).is_dir():
        return Path(env)
    hits = sorted(glob.glob(str(Path.home() / "re" / "ghidra_*")))
    return Path(hits[0]) if hits else None


@pytest.mark.ghidra
def test_lift_real_binary_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ghidra = _ghidra_dir()
    if ghidra is None:
        pytest.skip("no local Ghidra install found")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra))
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc not available")

    src = tmp_path / "prog.c"
    src.write_text(
        "#include <stdio.h>\n"
        "static int helper(int a){return a*3+1;}\n"
        'int main(void){printf("%d\\n", helper(5));return 0;}\n'
    )
    exe = tmp_path / "prog"
    subprocess.run([gcc, "-O1", str(src), "-o", str(exe)], check=True)

    from fw_diff.ghidra_lift import lift_image

    out = lift_image(str(exe), workdir=str(tmp_path))
    assert out.functions, "expected at least one lifted function"
    assert out.ghidra_version and out.ghidra_version != "unknown"
    names = {fn.name for fn in out.functions}
    assert "main" in names or any("main" in fn.symbols for fn in out.functions)

    # full pipeline: binary diffed against itself must be clean
    from fw_diff.pipeline import PipelineOptions, run_pipeline

    opts = PipelineOptions(out_dir=tmp_path / "out", deterministic=True, max_functions=40)
    result = run_pipeline(exe, exe, opts)
    assert result.facts.summary["functions"]["old"] > 0
    assert result.facts.summary["changed"] == 0
    assert result.facts.summary["added"] == 0
    assert result.facts.summary["removed"] == 0


@pytest.mark.ghidra
def test_lift_raw_flat_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Raw flat binary lift with --arch/--base (objcopy produces the payload)."""
    ghidra = _ghidra_dir()
    if ghidra is None:
        pytest.skip("no local Ghidra install found")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra))
    gcc, objcopy = shutil.which("gcc"), shutil.which("objcopy")
    if gcc is None or objcopy is None:
        pytest.skip("gcc/objcopy not available")

    src = tmp_path / "flat.c"
    src.write_text("int entry(int a){return a + 0x40;}\n")
    elf = tmp_path / "flat.elf"
    subprocess.run(
        [gcc, "-O2", "-nostdlib", "-nostartfiles", "-Wl,-e,entry", str(src), "-o", str(elf)],
        check=True,
    )
    raw = tmp_path / "flat.bin"
    subprocess.run(
        [objcopy, "-O", "binary", "--only-section=.text", str(elf), str(raw)], check=True
    )

    from fw_diff.ghidra_lift import lift_image

    out = lift_image(str(raw), arch="x86", base=0x400000, workdir=str(tmp_path))
    assert out.functions, "expected the raw entry function to lift"
    entry_fn = out.functions[0]
    # raw blobs carry no signature metadata: Ghidra recovers `entry` at the seeded base;
    # params may be 0 (unknown convention) — the code body is what must survive
    assert entry_fn.addr == 0x400000
    assert "+ 0x40" in entry_fn.pseudocode_raw
