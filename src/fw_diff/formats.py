"""Binary format detection for the AIO reverse-engineering surface (ROADMAP v0.4).

Covers: Windows PE (exe/dll/sys, incl. .NET assemblies), Android DEX, Nintendo Switch
NRO/NSO, UEFI firmware volumes, and container unpackers (ar/deb, generic 7z fallback for
MSI/CAB/DMG/7z/appx). Detection is intentionally conservative — sanity caps against
false positives (the Info.plist lesson from v0.3).
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

from .log import get_logger

log = get_logger("fw_diff.formats")

PE_MACHINES: dict[int, str] = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "armv7",
    0xAA64: "aarch64",
}
PE_KNOWN_MACHINES = set(PE_MACHINES)

DEX_MAGIC = b"dex\n"
NRO_MAGIC = b"NRO0"
NSO_MAGIC = b"NSO0"
FV_MAGIC = b"_FVH"  # at offset 0x28 of an EFI firmware volume header
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
MSI_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE/CFB (MSI, old Office docs)
CAB_MAGIC = b"MSCF"


def detect_pe(path: Path) -> tuple[str, int] | None:
    """Windows PE (exe/dll/sys/cpl). Returns (arch, 0) or None.

    Works for PE32 and PE32+; .NET assemblies are plain PE with a CLI header and are
    handled identically (Ghidra lifts the metadata).
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(0x100)
    except OSError:
        return None
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack("<I", head[0x3C:0x40])[0]
    if not 0x40 <= e_lfanew <= 0x1000:
        return None
    try:
        with path.open("rb") as fh:
            fh.seek(e_lfanew)
            pe = fh.read(24)
    except OSError:
        return None
    if len(pe) < 24 or pe[:4] != b"PE\x00\x00":
        return None
    machine = struct.unpack("<H", pe[4:6])[0]
    if machine not in PE_KNOWN_MACHINES:
        return None
    return PE_MACHINES[machine], 0


def detect_dex(path: Path) -> bool:
    """Android DEX (classes.dex). Ghidra's dex-reader lifts bytecode natively."""
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return head[:4] == DEX_MAGIC and head[4:7].isdigit()


def detect_switch(path: Path) -> tuple[str, int] | None:
    """Nintendo Switch NRO/NSO (magic at offset 0x10). Returns (arch, 0)."""
    try:
        with path.open("rb") as fh:
            fh.seek(0x10)
            magic = fh.read(4)
    except OSError:
        return None
    if magic in (NRO_MAGIC, NSO_MAGIC):
        return "aarch64", 0
    return None


def detect_uefi_fv(path: Path) -> bool:
    """EFI firmware volume ('_FVH' at offset 0x28). Ghidra parses FV contents."""
    try:
        with path.open("rb") as fh:
            fh.seek(0x28)
            magic = fh.read(4)
    except OSError:
        return False
    return magic == FV_MAGIC


def is_7z(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(6) == SEVENZ_MAGIC
    except OSError:
        return False


def is_msi(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(8) == MSI_MAGIC
    except OSError:
        return False


def is_cab(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(4) == CAB_MAGIC
    except OSError:
        return False


def _ext(path: Path) -> str:
    return path.suffix.lower()


def looks_like_dmg(path: Path) -> bool:
    return _ext(path) in (".dmg", ".sparseimage")


SEVENZ_BINARIES = ("7zz", "7za", "7z")


def sevenz_available() -> bool:
    return bool(shutil.which("7zz") or shutil.which("7za") or shutil.which("7z"))


def sevenz_extract(path: Path, out: Path, timeout_s: int) -> None:
    """Generic last-resort unpacker: MSI, CAB, DMG, 7z, appx, pkg (xar), ISO…"""
    resolved = next((full for b in SEVENZ_BINARIES if (full := shutil.which(b))), None)
    if resolved is None:  # pragma: no cover - guarded by sevenz_available upstream
        raise ValueError("no 7z tool available")
    subprocess.run(
        [resolved, "x", "-y", f"-o{out}", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout_s,
        check=False,
    )


def is_ar(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(8) == b"!<arch>\n"
    except OSError:
        return False


def ar_members(path: Path) -> list[tuple[str, bytes]]:
    """Parse a Unix ar archive (.deb is ar + tar members). Traversal-safe by name."""
    data = path.read_bytes()
    if data[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    members: list[tuple[str, bytes]] = []
    pos = 8
    long_names: list[str] = []
    while pos + 60 <= len(data):
        header = data[pos : pos + 60]
        name = header[0:16].decode("ascii", "replace").rstrip()
        size = int(header[48:58].decode("ascii", "replace").strip() or "0")
        body = data[pos + 60 : pos + 60 + size]
        pos += 60 + size + (size % 2)  # members are 2-byte aligned
        if name == "//":  # GNU long-name table
            long_names = [ln for ln in body.decode("ascii", "replace").split("\n") if ln]
            continue
        if name.endswith("/"):
            name = name[:-1]
        elif name.startswith("/") and name[1:].isdigit():
            idx = int(name[1:])
            name = long_names[idx] if idx < len(long_names) else name
        members.append((name, body))
    return members


def deb_extract(path: Path, out: Path, caps_timeout: int) -> list[str]:
    """Unpack a .deb (ar of debian-binary + control.tar.* + data.tar.*) into out.

    Returns notes. data.tar may be gz/xz/zst — stdlib covers gz/xz/bz2; zstd falls back
    to the zstandard package when present.
    """
    import gzip
    import lzma
    import tarfile

    notes: list[str] = []
    for name, body in ar_members(path):
        if name == "debian-binary":
            continue
        if not name.startswith("data.tar"):
            continue
        payload = body
        if payload[:2] == b"\x1f\x8b":
            payload = gzip.decompress(payload)
        elif payload[:6] == b"\xfd7zXZ\x00":
            payload = lzma.decompress(payload)
        elif payload[:2] == b"BZ":
            import bz2

            payload = bz2.decompress(payload)
        elif payload[:4] == b"\x28\xb5\x2f\xfd":
            try:
                import zstandard  # type: ignore[import-not-found]

                payload = zstandard.ZstdDecompressor().decompress(payload)
                notes.append("data.tar.zst decoded via zstandard")
            except ImportError:
                notes.append("data.tar.zst found but 'zstandard' not installed — skipped")
                continue
        inner = out / name
        inner.write_bytes(payload)
        with tarfile.open(inner) as tf:
            tf.extractall(out, filter="data")
        notes.append(f"deb member {name} extracted")
    return notes


def rpm_to_cpio(path: Path, out: Path, caps_timeout: int) -> bool:
    """Convert an .rpm payload via the rpm2cpio tool when available (then cpio handles it)."""
    rpm2cpio = shutil.which("rpm2cpio")
    cpio = shutil.which("cpio")
    if rpm2cpio is None or cpio is None:
        return False
    with (out / "payload.cpio").open("wb") as dst:
        subprocess.run(
            [rpm2cpio, str(path)],
            stdout=dst,
            stderr=subprocess.DEVNULL,
            timeout=caps_timeout,
            check=False,
        )
    subprocess.run(
        [cpio, "-id", "--no-absolute-filenames"],
        cwd=out,
        stdin=(out / "payload.cpio").open("rb"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=caps_timeout,
        check=False,
    )
    (out / "payload.cpio").unlink(missing_ok=True)
    return True


def detect_binary(path: Path) -> str | None:
    """Central AIO detector: arch string for any lift-able binary, else None.

    Covers ELF (any Ghidra arch), Mach-O/FAT (iOS/macOS), PE (Windows), DEX (Android),
    Switch NRO/NSO, and UEFI firmware volumes. Used by tree scans and package selection.
    """
    from .ingest import detect_elf  # late import: ingest imports this module
    from .ios import detect_macho

    elf = detect_elf(path)
    if elf is not None:
        return elf[0]
    macho = detect_macho(path)
    if macho is not None:
        return macho[0]
    pe = detect_pe(path)
    if pe is not None:
        return pe[0]
    if detect_dex(path):
        return "dex"
    switch = detect_switch(path)
    if switch is not None:
        return switch[0]
    if detect_uefi_fv(path):
        return "uefi_fv"
    return None
