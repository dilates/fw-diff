"""iOS app support (ROADMAP v0.3): .ipa bundles, Mach-O / FAT binaries, Info.plist notes.

An .ipa is a ZIP containing ``Payload/<App>.app/<Executable>`` (Mach-O, usually arm64)
plus embedded frameworks/dylibs. Ghidra's Mach-O loader handles the lifting; this module
adds detection, safe unpacking, slice selection for FAT binaries, and bundle metadata.
"""

from __future__ import annotations

import plistlib
import struct
import zipfile
from pathlib import Path

from .log import get_logger

log = get_logger("fw_diff.ios")

MAGIC_ZIP = b"PK\x03\x04"

# Mach-O magics (32/64 + swapped) and fat (universal) magics
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

MH_EXECUTE = 0x2  # main executable
MH_DYLIB = 0x6

CPU_ARCH = {
    0x00000007: "x86",
    0x0000000C: "armv7",
    0x01000007: "x86_64",
    0x0100000C: "aarch64",
}

MAX_IPA_ENTRIES = 100_000
MAX_IPA_BYTES = 4 * 1024**3


def detect_macho(path: Path) -> tuple[str, int, int] | None:
    """Return (arch, filetype, offset) for Mach-O / universal binaries, else None.

    For FAT (universal) binaries, the first arm64 slice (falling back to the first
    slice) is selected and its absolute offset within the file is returned.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if len(head) < 32:
        return None
    magic = struct.unpack(">I", head[:4])[0]
    magic_le = struct.unpack("<I", head[:4])[0]
    if magic in (FAT_MAGIC, FAT_CIGAM) or magic_le in (FAT_MAGIC, FAT_CIGAM):
        return _detect_fat(head, big_endian=magic == FAT_MAGIC)
    # both 32/64-bit headers are 8x u32 (magic cputype subtype filetype ncmds size
    # flags [reserved]); the reserved field is u32 even on 64-bit
    endian = "<" if magic_le in (MH_MAGIC_64, MH_MAGIC) else ">"
    fmt = "IIIIIIII"
    size = struct.calcsize(fmt)
    fields = struct.unpack(endian + fmt, head[:size])
    _magic, cputype, _subtype, filetype, ncmds, sizeofcmds = (
        fields[0],
        fields[1],
        fields[2],
        fields[3],
        fields[4],
        fields[5],
    )
    if filetype not in (1, 2, 5, 6, 7, 8, 9, 11, 12, 13):  # known MH_ filetypes
        return None
    if ncmds > 4096 or sizeofcmds > 1 << 24:  # sanity caps against false positives
        return None
    arch = CPU_ARCH.get(cputype, f"cputype_{cputype:#x}")
    return arch, filetype, 0


def _detect_fat(head: bytes, big_endian: bool) -> tuple[str, int, int] | None:
    fmt = ">I" if big_endian else "<I"
    nfat = struct.unpack(fmt, head[4:8])[0]
    slices: list[tuple[int, int, int]] = []  # (cputype, offset, size)
    for i in range(min(nfat, 8)):
        off = 8 + i * 20
        if off + 20 > len(head):
            break
        cputype, _subtype, offset, size, _align = struct.unpack(
            (">IIIII" if big_endian else "<IIIII"), head[off : off + 20]
        )
        slices.append((cputype, offset, size))
    if not slices:
        return None
    preferred = next((s for s in slices if s[0] == 0x0100000C), slices[0])  # arm64 first
    cputype, offset, _size = preferred
    arch = CPU_ARCH.get(cputype, f"cputype_{cputype:#x}")
    return arch, MH_EXECUTE, offset  # fat members are executables/dylibs; lift as-is


def macho_slice(path: Path, offset: int) -> bytes:
    """Bytes of one Mach-O (used to carve a slice out of a FAT binary)."""
    if offset == 0:
        return path.read_bytes()
    data = path.read_bytes()[offset:]
    if not data.startswith(struct.pack("<I", MH_MAGIC_64)):
        # byte order: re-check both magic orders before trusting the carve
        head = data[:4]
        if head not in (struct.pack("<I", MH_MAGIC_64), struct.pack(">I", MH_MAGIC_64)):
            log.warning(
                "carved slice is not a 64-bit Mach-O; lifting whole file", extra={"count": 1}
            )
            return path.read_bytes()
    return data


def is_ipa(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(4) == MAGIC_ZIP
    except OSError:
        return False


def _safe_zip_extract(zip_path: Path, out: Path) -> int:
    """Traversal-safe zip extraction with caps (THREAT_MODEL 3.1)."""
    entries = 0
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            entries += 1
            if entries > MAX_IPA_ENTRIES:
                raise ValueError("ipa exceeds max_entries cap")
            name = member.filename
            if name.startswith("/") or "\\" in name or ".." in Path(name).parts:
                raise ValueError(f"unsafe path in ipa: {name!r}")
            total += member.file_size
            if total > MAX_IPA_BYTES:
                raise ValueError("ipa exceeds max_total_bytes cap")
            target = (out / name).resolve()
            if not str(target).startswith(str(out.resolve())):
                raise ValueError(f"path traversal in ipa: {name!r}")
        zf.extractall(out)
    return entries


def bundle_notes(app_dir: Path) -> list[str]:
    """Info.plist metadata for the manifest audit trail (bundle id + version)."""
    plist = app_dir / "Info.plist"
    if not plist.is_file():
        return []
    try:
        with plist.open("rb") as fh:
            data = plistlib.load(fh)
        bundle_id = data.get("CFBundleIdentifier", "?")
        version = data.get("CFBundleShortVersionString") or data.get("CFBundleVersion", "?")
        name = data.get("CFBundleDisplayName") or data.get("CFBundleName", "?")
        return [f"ios bundle: {name} ({bundle_id}) version {version}"]
    except (plistlib.InvalidFileException, OSError, ValueError) as exc:
        log.debug("Info.plist unreadable: %s", exc)
        return [f"Info.plist present but unreadable ({type(exc).__name__})"]


def find_app_bundles(tree: Path) -> list[Path]:
    """Payload/*.app directories inside an unpacked ipa tree (any depth — zip layouts
    extract under intermediate dirs)."""
    return sorted(p for p in tree.rglob("*.app") if p.is_dir() and p.parent.name == "Payload")


def select_ios_targets(tree: Path, max_targets: int) -> tuple[list[tuple[Path, str]], list[str]]:
    """Pick lift targets from an unpacked .app bundle(s).

    Main executable first (Mach-O filetype MH_EXECUTE named like the bundle), then
    embedded frameworks/dylibs (MH_DYLIB / any other Mach-O), capped.
    """
    notes: list[str] = []
    targets: list[tuple[Path, str]] = []
    for app in find_app_bundles(tree):
        notes.extend(bundle_notes(app))
        machos: list[tuple[Path, str, int, int]] = []
        for p in sorted(app.rglob("*")):
            if not p.is_file() or p.is_symlink():
                continue
            found = detect_macho(p)
            if found is not None:
                arch, filetype, offset = found
                machos.append((p, arch, filetype, offset))
        if not machos:
            continue
        expected_name = app.stem
        main = next(
            (m for m in machos if m[2] == MH_EXECUTE and m[0].stem == expected_name),
            next((m for m in machos if m[2] == MH_EXECUTE), None),
        )
        if main is not None:
            targets.append((main[0], main[1]))
            if main[3] != 0:  # fat binary -> carve the preferred slice
                carved = main[0].with_suffix(".fwdiff-slice")
                carved.write_bytes(macho_slice(main[0], main[3]))
                targets[-1] = (carved, main[1])
                notes.append(f"carved arm64 slice from fat binary {main[0].name}")
        for m in machos:
            if main is not None and m[0] == main[0]:
                continue
            if len(targets) >= max_targets:
                notes.append(f"{len(machos) - max_targets} Mach-O files beyond cap skipped")
                break
            targets.append((m[0], m[1]))
    return targets, notes
