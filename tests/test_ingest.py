"""Ingest tests: detection, unpacking, caps (gcc available in CI/dev)."""

from __future__ import annotations

import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from fw_diff.ingest import IngestError, ResourceCaps, detect_elf, ingest

GCC = shutil.which("gcc")


@pytest.fixture()
def tiny_elf(tmp_path: Path) -> Path:
    if GCC is None:
        pytest.skip("gcc not available")
    src = tmp_path / "t.c"
    src.write_text('#include <stdio.h>\nint main(void){printf("hi\\n");return 0;}\n')
    exe = tmp_path / "tiny"
    subprocess.run([GCC, "-O0", str(src), "-o", str(exe)], check=True)
    return exe


def test_detect_elf(tiny_elf: Path) -> None:
    arch, little = detect_elf(tiny_elf)
    assert arch in ("x86", "x86_64")
    assert little is True


def test_ingest_elf_single_target(tiny_elf: Path, tmp_path: Path) -> None:
    manifest = ingest(tiny_elf, tmp_path / "work", ResourceCaps())
    assert manifest.formats == ["elf"]
    assert len(manifest.targets) == 1
    assert manifest.targets[0].arch in ("x86", "x86_64")
    assert manifest.targets[0].base is None


def test_ingest_raw_requires_base(tmp_path: Path) -> None:
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x90" * 256)  # NOP sled: genuinely raw, no format magic
    with pytest.raises(IngestError, match="--base"):
        ingest(raw, tmp_path / "work", ResourceCaps())
    manifest = ingest(raw, tmp_path / "work", ResourceCaps(), arch="x86", base=0x40000000)
    assert manifest.formats == ["raw"]
    assert manifest.targets[0].base == 0x40000000
    assert manifest.targets[0].path == str(raw)


def test_ingest_tar_gz_with_elf_inside(tiny_elf: Path, tmp_path: Path) -> None:
    tree = tmp_path / "bundle"
    tree.mkdir()
    (tree / "fw.bin").write_bytes(tiny_elf.read_bytes())
    tar = tmp_path / "fw.tar.gz"
    with tarfile.open(tar, "w:gz") as tf:
        tf.add(tree / "fw.bin", arcname="fw.bin")
    manifest = ingest(tar, tmp_path / "work", ResourceCaps())
    assert "gzip" in manifest.formats or "tar" in manifest.formats
    assert "tree:elf" in manifest.formats
    assert manifest.targets and manifest.targets[0].arch in ("x86", "x86_64")


def test_ingest_missing_file(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="not found"):
        ingest(tmp_path / "nope.bin", tmp_path / "work", ResourceCaps())


def test_caps_reject_symlinks(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "link").symlink_to("/etc/passwd")
    tar = tmp_path / "evil.tar"
    with tarfile.open(tar, "w") as tf:
        tf.add(tree / "link", arcname="link")
    with pytest.raises((IngestError, tarfile.TarError)):
        ingest(tar, tmp_path / "work", ResourceCaps())


def test_choose_pair_targets_notes_multi(tmp_path: Path, tiny_elf: Path) -> None:
    manifest = ingest(tiny_elf, tmp_path / "w", ResourceCaps())
    manifest.targets.append(manifest.targets[0])
    from fw_diff.ingest import choose_pair_targets

    a, b = choose_pair_targets(manifest, manifest)
    assert "v0.1 lifts first of 2 targets" in manifest.notes
    assert a is b or a == b
