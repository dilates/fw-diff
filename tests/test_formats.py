"""AIO format tests (v0.4): PE, DEX, Switch, UEFI, .deb, .apk, directory ingest."""

from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from fw_diff import formats as fmt_mod
from fw_diff.ingest import IngestError, ResourceCaps, ingest

GCC = pytest.importorskip if False else None  # gcc availability checked in fixtures


def _gcc() -> str | None:
    import shutil

    return shutil.which("gcc")


def _elf(tmp_path: Path) -> bytes:
    if not _gcc():
        pytest.skip("gcc not available")
    src = tmp_path / "t.c"
    src.write_text("int main(void){return 0;}\n")
    exe = tmp_path / "t"
    subprocess_run_gcc(src, exe)
    return exe.read_bytes()


def subprocess_run_gcc(src: Path, exe: Path) -> None:
    import subprocess

    subprocess.run(["gcc", "-O0", str(src), "-o", str(exe)], check=True)


def _pe(machine: int = 0x8664) -> bytes:
    """Minimal-but-sane PE: MZ + e_lfanew -> PE signature + COFF with machine type."""
    dos = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<IHHIIIHH", 0x00004550, machine, 1, 0, 0, 0, 0xF0, 0x22)
    return bytes(dos) + coff


def test_detect_pe(tmp_path: Path) -> None:
    for machine, arch in (
        (0x8664, "x86_64"),
        (0x014C, "x86"),
        (0xAA64, "aarch64"),
        (0x01C0, "armv7"),
    ):
        exe = tmp_path / f"app_{machine:#x}.exe"
        exe.write_bytes(_pe(machine))
        assert fmt_mod.detect_pe(exe) == (arch, 0)


def test_detect_pe_rejects_garbage(tmp_path: Path) -> None:
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"MZ" + b"\x00" * 60)  # no PE signature
    assert fmt_mod.detect_pe(bad) is None
    bad.write_bytes(_pe(0x6329))  # unknown machine (MIPS little-endian PE)
    assert fmt_mod.detect_pe(bad) is None


def test_ingest_pe(tmp_path: Path) -> None:
    exe = tmp_path / "app.exe"
    exe.write_bytes(_pe())
    manifest = ingest(exe, tmp_path / "work", ResourceCaps())
    assert manifest.formats == ["pe"]
    assert manifest.targets[0].arch == "x86_64"


def _dex() -> bytes:
    return b"dex\n035\x00" + b"\x00" * 24


def test_detect_dex_and_ingest(tmp_path: Path) -> None:
    dex = tmp_path / "classes.dex"
    dex.write_bytes(_dex())
    assert fmt_mod.detect_dex(dex) is True
    manifest = ingest(dex, tmp_path / "work", ResourceCaps())
    assert manifest.formats == ["dex"]
    assert manifest.targets[0].arch == "dex"


def test_detect_switch(tmp_path: Path) -> None:
    nso = tmp_path / "main.nso"
    nso.write_bytes(b"\x00" * 0x10 + b"NSO0" + b"\x00" * 32)
    assert fmt_mod.detect_switch(nso) == ("aarch64", 0)
    manifest = ingest(nso, tmp_path / "work", ResourceCaps())
    assert manifest.targets[0].arch == "aarch64"


def test_detect_uefi_fv(tmp_path: Path) -> None:
    fv = bytearray(b"\x00" * 0x40)
    fv[0x28:0x2C] = b"_FVH"
    vol = tmp_path / "fv.bin"
    vol.write_bytes(bytes(fv))
    assert fmt_mod.detect_uefi_fv(vol) is True
    manifest = ingest(vol, tmp_path / "work", ResourceCaps())
    assert manifest.formats == ["uefi"]
    assert manifest.targets[0].arch == "uefi_fv"


def test_ingest_deb(tmp_path: Path) -> None:
    """Real .deb assembled in-test: ar(debian-binary + control.tar.gz + data.tar.gz)."""
    tree = tmp_path / "data"
    (tree / "usr" / "bin").mkdir(parents=True)
    (tree / "usr" / "bin" / "tool").write_bytes(_elf(tmp_path))
    data_tar = tmp_path / "data.tar.gz"
    with tarfile.open(data_tar, "w:gz") as tf:
        tf.add(tree, arcname=".")
    control_tar = tmp_path / "control.tar.gz"
    with tarfile.open(control_tar, "w:gz") as tf:
        ctrl = tmp_path / "control"
        ctrl.write_bytes(b"Package: tool\n")
        tf.add(ctrl, arcname="./control")

    def _ar_member(name: str, body: bytes) -> bytes:
        header = (
            name.ljust(16).encode()
            + b"0".ljust(12)  # mtime
            + b"0".ljust(6)  # uid
            + b"0".ljust(6)  # gid
            + b"100644".ljust(8)  # mode
            + str(len(body)).ljust(10).encode()  # size (space-padded decimal)
            + b"`\n"
        )
        padding = b"\n" if len(body) % 2 else b""
        return header + body + padding

    deb = tmp_path / "tool.deb"
    deb.write_bytes(
        b"!<arch>\n"
        + _ar_member("debian-binary", b"2.0\n")
        + _ar_member("control.tar.gz", control_tar.read_bytes())
        + _ar_member("data.tar.gz", data_tar.read_bytes())
    )

    manifest = ingest(deb, tmp_path / "work", ResourceCaps())
    assert "ar" in manifest.formats
    assert any("data.tar" in n for n in manifest.notes)
    assert manifest.targets, "ELF inside the deb must become a lift target"
    assert manifest.targets[0].arch in ("x86", "x86_64")


def test_ingest_apk(tmp_path: Path) -> None:
    """APK: lib/<abi>/*.so + classes.dex -> native libs first, then dex."""
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fake-axml")
        zf.writestr("classes.dex", _dex())
        zf.writestr("classes2.dex", _dex())
        zf.writestr("lib/arm64-v8a/libnative.so", _elf(tmp_path))
        zf.writestr("res/layout.xml", b"\x03\x00\x08\x00fake")
    manifest = ingest(apk, tmp_path / "work", ResourceCaps())
    assert "android:apk" in manifest.formats
    assert any("arm64-v8a" in n for n in manifest.notes)
    archs = [t.arch for t in manifest.targets]
    assert archs[0] in ("x86", "x86_64")  # native lib (ELF) first
    assert "dex" in archs
    assert any("classes" in t.path for t in manifest.targets)


def test_ingest_directory(tmp_path: Path) -> None:
    tree = tmp_path / "extracted"
    (tree / "lib").mkdir(parents=True)
    (tree / "lib" / "core.so").write_bytes(_elf(tmp_path))
    (tree / "bin.exe").write_bytes(_pe())
    manifest = ingest(tree, tmp_path / "work", ResourceCaps())
    assert manifest.formats == ["dir", "tree:binaries"]
    archs = sorted(t.arch for t in manifest.targets)
    assert "x86_64" in archs  # PE picked up from the tree
    assert any(t.arch in ("x86", "x86_64") for t in manifest.targets)


def test_ingest_empty_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(IngestError, match="no lift-able binaries"):
        ingest(empty, tmp_path / "work", ResourceCaps())


def test_sevenz_without_tools(tmp_path: Path) -> None:
    if fmt_mod.sevenz_available():
        pytest.skip("7z installed")
    blob = tmp_path / "x.7z"
    blob.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 16)
    with pytest.raises(IngestError, match="7z"):
        ingest(blob, tmp_path / "work", ResourceCaps())


def test_rpm_without_tools(tmp_path: Path) -> None:
    import shutil

    if shutil.which("rpm2cpio") and shutil.which("cpio"):
        pytest.skip("rpm tools installed")
    rpm = tmp_path / "pkg.rpm"
    rpm.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 100)
    with pytest.raises(IngestError, match="rpm2cpio"):
        ingest(rpm, tmp_path / "work", ResourceCaps())


_ = io, gzip  # stdlib parity with formats module
