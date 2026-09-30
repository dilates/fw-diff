"""iOS support tests: Mach-O detection, FAT slices, .ipa ingest, plist metadata."""

from __future__ import annotations

import plistlib
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from fw_diff import ios as ios_fmt
from fw_diff.ingest import IngestError, ResourceCaps, ingest

MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
MH_EXECUTE = 0x2
MH_DYLIB = 0x6


def _macho64(cputype: int = 0x0100000C, filetype: int = MH_EXECUTE) -> bytes:
    """Minimal-but-valid 64-bit Mach-O header + one zero load command."""
    header = struct.pack("<IIIIIIII", MH_MAGIC_64, cputype, 0, filetype, 1, 0x20, 0, 0)
    # one empty load command (cmd=0, cmdsize=0x20 is invalid; use a minimal segment-ish
    # placeholder: cmd=0x19 LC_UUID, cmdsize=0x24, 16 zero bytes)
    uuid_cmd = struct.pack("<II", 0x19, 0x24) + b"\x00" * 16
    return header + uuid_cmd


def _macho32(cputype: int = 0x0000000C, filetype: int = MH_EXECUTE) -> bytes:
    header = struct.pack("<IIIIIIII", MH_MAGIC, cputype, 0, filetype, 1, 0x20, 0, 0)
    uuid_cmd = struct.pack("<II", 0x19, 0x24) + b"\x00" * 16
    return header + uuid_cmd


def _fat(slices: list[tuple[int, bytes]]) -> bytes:
    """Assemble a fat (universal) binary from (cputype, slice_bytes) pairs."""
    offsets = []
    pos = 8 + 20 * len(slices)
    for _cpu, blob in slices:
        offsets.append(pos)
        pos += len(blob)
    head = struct.pack(">II", 0xCAFEBABE, len(slices))
    for (cpu, blob), off in zip(slices, offsets, strict=True):
        head += struct.pack(">IIIII", cpu, 0, off, len(blob), 0x4000)
    return head + b"".join(blob for _, blob in slices)


def test_detect_macho_arm64(tmp_path: Path) -> None:
    exe = tmp_path / "App"
    exe.write_bytes(_macho64())
    found = ios_fmt.detect_macho(exe)
    assert found is not None
    arch, filetype, offset = found
    assert arch == "aarch64" and filetype == MH_EXECUTE and offset == 0


def test_detect_macho_dylib_and_swapped(tmp_path: Path) -> None:
    dylib = tmp_path / "lib.dylib"
    dylib.write_bytes(_macho64(filetype=MH_DYLIB))
    assert ios_fmt.detect_macho(dylib)[1] == MH_DYLIB  # type: ignore[index]
    swapped = tmp_path / "swapped"
    swapped.write_bytes(struct.pack(">IIIIIIII", MH_MAGIC_64, 0x0100000C, 0, 0x2, 1, 0x20, 0, 0))
    assert ios_fmt.detect_macho(swapped) is not None


def test_detect_fat_prefers_arm64_slice(tmp_path: Path) -> None:
    fat = tmp_path / "fat"
    fat.write_bytes(_fat([(0x00000007, _macho32(0x00000007)), (0x0100000C, _macho64())]))
    found = ios_fmt.detect_macho(fat)
    assert found is not None
    arch, _filetype, offset = found
    assert arch == "aarch64"
    assert offset > 0
    carved = ios_fmt.macho_slice(fat, offset)
    assert carved.startswith(struct.pack("<I", MH_MAGIC_64))


def test_macho_not_elf(tmp_path: Path) -> None:
    from fw_diff.ingest import detect_elf

    exe = tmp_path / "App"
    exe.write_bytes(_macho64())
    assert detect_elf(exe) is None  # no cross-detection confusion


def test_ingest_ipa(tmp_path: Path) -> None:
    """Full .ipa ingest: Payload/X.app main exe first, framework dylib second."""
    app = tmp_path / "Payload" / "MyApp.app"
    app.mkdir(parents=True)
    (app / "MyApp").write_bytes(_macho64())  # main executable (name matches bundle)
    (app / "Framework.dylib").write_bytes(_macho64(filetype=MH_DYLIB))
    info = {
        "CFBundleIdentifier": "com.example.myapp",
        "CFBundleShortVersionString": "2.1.0",
        "CFBundleName": "MyApp",
    }
    (app / "Info.plist").write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
    ipa = tmp_path / "MyApp.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.write(app / "MyApp", "Payload/MyApp.app/MyApp")
        zf.write(app / "Framework.dylib", "Payload/MyApp.app/Framework.dylib")
        zf.write(app / "Info.plist", "Payload/MyApp.app/Info.plist")

    manifest = ingest(ipa, tmp_path / "work", ResourceCaps())
    assert "zip" in manifest.formats
    assert "ios:ipa" in manifest.formats
    assert len(manifest.targets) == 2
    assert manifest.targets[0].arch == "aarch64"
    assert manifest.targets[0].path.endswith("MyApp")  # main executable first
    assert manifest.targets[1].arch == "aarch64"
    assert any("com.example.myapp" in n for n in manifest.notes)
    assert any("2.1.0" in n for n in manifest.notes)


def test_ingest_bare_macho(tmp_path: Path) -> None:
    exe = tmp_path / "payload.bin"
    exe.write_bytes(_macho64(0x01000007))  # x86_64
    manifest = ingest(exe, tmp_path / "work", ResourceCaps())
    assert manifest.formats == ["macho"]
    assert manifest.targets[0].arch == "x86_64"


def test_ingest_ipa_rejects_traversal(tmp_path: Path) -> None:
    ipa = tmp_path / "evil.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("../escape.txt", "x")
    with pytest.raises(IngestError, match="unsafe path"):
        ingest(ipa, tmp_path / "work", ResourceCaps())


def test_ipa_too_large(tmp_path: Path) -> None:
    ipa = tmp_path / "big.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/X.app/X", b"\x00" * 5 * 1024**3)
    with pytest.raises(IngestError, match="max_total_bytes"):
        ingest(ipa, tmp_path / "work", ResourceCaps())


@pytest.mark.ghidra
def test_ghidra_lifts_macho(tmp_path: Path) -> None:
    """Ghidra lift of a real Mach-O — requires a local sample (no macOS toolchain on
    Linux CI). Provide one via FW_DIFF_IOS_SAMPLE pointing at a Mach-O file."""
    sample = Path(__import__("os").environ.get("FW_DIFF_IOS_SAMPLE", ""))
    if not sample.is_file() or ios_fmt.detect_macho(sample) is None:
        pytest.skip("no local Mach-O sample (set FW_DIFF_IOS_SAMPLE)")
    from fw_diff.ghidra_lift import lift_image

    out = lift_image(str(sample), workdir=str(tmp_path))
    assert out.ghidra_version
    assert isinstance(out.functions, list)


_ = tarfile  # parity with ingest imports
