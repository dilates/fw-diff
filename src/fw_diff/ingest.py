"""Ingest: format detection, unpacking with resource caps, lift-target selection.

Implements pipeline-spec §1. Untrusted input: caps are mandatory (THREAT_MODEL §3.1) —
configurable, but never disableable in `ci` mode.
"""

from __future__ import annotations

import gzip
import hashlib
import shutil
import struct
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import android as android_fmt
from . import ios as ios_fmt
from .log import get_logger
from .models import ImageManifest, LiftTarget

log = get_logger("fw_diff.ingest")

MAGIC_ELF = b"\x7fELF"
MAGIC_SQUASHFS = (b"hsqs", b"sqsh")
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_CPIO = (b"070701", b"070702")
MAGIC_UBOOT = b"\x27\x05\x19\x56"
MAGIC_UBI = b"UBI#"

EM_MAP: dict[int, str] = {
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    40: "armv7",
    62: "x86_64",
    183: "aarch64",
    243: "riscv64",
    244: "riscv32",
}

MAX_LIFT_TARGETS = 24
MAX_UNPACK_DEPTH = 3  # nested archives (e.g. tar.gz -> squashfs -> tree)


class IngestError(ValueError):
    """Exit-code-2 condition: unusable input, no partial state (ARCHITECTURE §8)."""


@dataclass(frozen=True)
class ResourceCaps:
    max_total_bytes: int = 2 * 1024**3
    max_depth: int = 8
    max_entries: int = 100_000
    timeout_s: int = 1800

    def harder(self) -> ResourceCaps:
        """Hard caps used in ci mode (pipeline-spec §1.2)."""
        return ResourceCaps(
            max_total_bytes=min(self.max_total_bytes, 2 * 1024**3),
            max_depth=min(self.max_depth, 8),
            max_entries=min(self.max_entries, 100_000),
            timeout_s=min(self.timeout_s, 1800),
        )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_elf(path: Path) -> tuple[str, bool] | None:
    """Return (arch, little_endian) if the file is an ELF, else None."""
    try:
        with path.open("rb") as fh:
            head = fh.read(20)
    except OSError:
        return None
    if len(head) < 20 or not head.startswith(MAGIC_ELF):
        return None
    ei_data = head[5]
    width = {1: "<", 2: ">"}[ei_data]
    machine = struct.unpack(f"{width}H", head[18:20])[0]
    return EM_MAP.get(machine, f"em_{machine}"), ei_data == 1


def _detect_format(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if head.startswith(MAGIC_ELF):
        return "elf"
    if head[:4] in MAGIC_SQUASHFS:
        return "squashfs"
    if head.startswith(MAGIC_GZIP):
        return "gzip"
    if head[:6] in MAGIC_CPIO:
        return "cpio"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith(MAGIC_UBOOT):
        return "uboot"
    if head[:4] == ios_fmt.MAGIC_ZIP:
        return "zip"
    if android_fmt.detect_sparse(path):
        return "sparse_android"
    if head.startswith(MAGIC_UBI):
        return "ubi"
    if ios_fmt.detect_macho(path) is not None:
        return "macho"
    return None


def _extract_one(path: Path, fmt: str, out: Path, caps: ResourceCaps) -> None:
    if fmt == "tar":
        with tarfile.open(path) as tf:
            tf.extractall(out, filter="data")
    elif fmt == "cpio":
        cpio = shutil.which("cpio")
        if cpio is None:
            raise IngestError("cpio archive detected but the 'cpio' tool is not installed")
        with path.open("rb") as fh:
            subprocess.run(
                [cpio, "-id", "--no-absolute-filenames"],
                cwd=out,
                stdin=fh,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=caps.timeout_s,
                check=False,
            )
    elif fmt == "squashfs":
        unsquashfs = shutil.which("unsquashfs")
        if unsquashfs is None:
            raise IngestError("squashfs detected but 'unsquashfs' is not installed")
        subprocess.run(
            [unsquashfs, "-d", str(out), "-no-progress", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=caps.timeout_s,
            check=False,
        )
    elif fmt == "zip":
        try:
            ios_fmt._safe_zip_extract(path, out)
        except (zipfile.BadZipFile, ValueError) as exc:
            raise IngestError(f"zip extraction failed: {exc}") from exc
    else:  # pragma: no cover - guarded by _detect_format dispatch
        raise IngestError(f"unknown archive format {fmt}")


def _gunzip(path: Path, out: Path, caps: ResourceCaps) -> None:
    with gzip.open(path, "rb") as src, out.open("wb") as dst:
        shutil.copyfileobj(src, dst, length=1 << 20)
    if out.stat().st_size > caps.max_total_bytes:
        raise IngestError("gunzipped image exceeds max_total_bytes cap")


def _enforce_caps(workdir: Path, caps: ResourceCaps) -> tuple[int, int]:
    entries = 0
    total = 0
    for p in sorted(workdir.rglob("*")):
        if p.is_symlink():
            raise IngestError(f"symlink in extracted tree is not allowed: {p.name}")
        entries += 1
        if entries > caps.max_entries:
            raise IngestError("extracted tree exceeds max_entries cap")
        if p.is_file():
            total += p.stat().st_size
            if total > caps.max_total_bytes:
                raise IngestError("extracted tree exceeds max_total_bytes cap")
    return entries, total


def _unpack_chain(
    cur: Path, workdir: Path, caps: ResourceCaps, formats: list[str], notes: list[str]
) -> Path:
    """Unpack archive formats recursively (depth-capped); returns the final payload path."""
    for _ in range(MAX_UNPACK_DEPTH):
        fmt = _detect_format(cur)
        if fmt in (None, "elf", "macho"):
            break
        formats.append(fmt)
        if fmt == "gzip":
            out = workdir / f"gunzipped_{len(formats)}"
            _gunzip(cur, out, caps)
            cur = out
            continue
        if fmt == "uboot":
            out = workdir / f"uboot_payload_{len(formats)}"
            out.write_bytes(cur.read_bytes()[64:])
            notes.append("u-boot legacy header (64 bytes) stripped")
            cur = out
            continue
        if fmt == "sparse_android":
            out = workdir / f"raw_{len(formats)}.img"
            out.write_bytes(android_fmt.sparse_to_raw(cur))
            notes.append("Android sparse image converted to raw")
            inner = _scan_carvable(out)
            if inner is not None:
                formats.append("tree:carved")
                return out
            cur = out
            continue
        if fmt == "ubi":
            out = workdir / f"ubi_out_{len(formats)}"
            out.mkdir(parents=True, exist_ok=True)
            tool = shutil.which("ubireader_extract_files")
            if tool is None:
                notes.append(
                    "UBI image detected but ubi-reader not installed "
                    "(pip install 'fw-diff[containers]') — raw scan only"
                )
            else:
                subprocess.run(
                    [tool, str(cur), "-o", str(out)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=caps.timeout_s,
                    check=False,
                )
                notes.append("UBI/UBIFS files extracted via ubi-reader")
            formats.append("tree")
            return out if out.exists() and any(out.iterdir()) else workdir
        out = workdir / f"unpacked_{len(formats)}"
        out.mkdir(parents=True, exist_ok=True)
        _extract_one(cur, fmt, out, caps)
        inner = _first_inner_archive(out)
        if inner is None:
            formats.append("tree")
            return out
        cur = inner
        notes.append(f"nested archive: {inner.name}")
    return cur


def _scan_carvable(raw: Path) -> Path | None:
    """Carve embedded ELFs from a raw image; returns the carved dir when found."""
    out_dir = raw.parent / "carve"
    carved = android_fmt.carve_to_files(raw, raw.parent)
    return out_dir if carved else None


def _first_inner_archive(tree: Path) -> Path | None:
    for p in sorted(tree.rglob("*")):
        if p.is_file() and not p.is_symlink():
            fmt = _detect_format(p)
            if fmt in ("gzip", "squashfs", "cpio", "tar", "uboot", "zip"):
                return p
    return None


def ingest(
    path: Path,
    workdir: Path,
    caps: ResourceCaps,
    *,
    arch: str | None = None,
    base: int | None = None,
) -> ImageManifest:
    """Detect, unpack (with caps), and choose lift targets for one image."""
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"input not found: {path}")
    manifest = ImageManifest(path=str(path), sha256=sha256_file(path))
    workdir.mkdir(parents=True, exist_ok=True)

    fmt = _detect_format(path)
    if fmt == "elf" and base is None:
        found = detect_elf(path)
        assert found is not None
        target_arch = arch or found[0]
        manifest.formats.append("elf")
        if arch and arch != found[0]:
            manifest.notes.append(f"--arch {arch} overrides detected {found[0]}")
        manifest.targets.append(LiftTarget(path=str(path), arch=target_arch, base=None))
    elif fmt == "elf" and base is not None:
        manifest.formats.append("elf")
        manifest.targets.append(LiftTarget(path=str(path), arch=arch or "unknown", base=base))
        manifest.notes.append("ELF lifted at explicit --base")
    elif fmt == "macho" and base is None:
        macho = ios_fmt.detect_macho(path)
        assert macho is not None
        macho_arch, _filetype, slice_offset = macho
        target_arch = arch or macho_arch
        manifest.formats.append("macho")
        if slice_offset != 0:  # fat binary: carve preferred slice
            carved = path.with_suffix(".fwdiff-slice")
            carved.write_bytes(ios_fmt.macho_slice(path, slice_offset))
            manifest.targets.append(LiftTarget(path=str(carved), arch=macho_arch, base=None))
            manifest.notes.append(f"carved slice from fat binary {path.name}")
        else:
            manifest.targets.append(LiftTarget(path=str(path), arch=target_arch, base=None))
        if arch and arch != macho_arch:
            manifest.notes.append(f"--arch {arch} overrides detected {macho_arch}")
    elif base is not None:
        manifest.formats.append("raw")
        manifest.targets.append(LiftTarget(path=str(path), arch=arch or "unknown", base=base))
        manifest.notes.append("raw flat binary mode (--base)")
    elif fmt is None:
        raise IngestError(
            "input is not ELF and no container format was detected; for raw flat binaries "
            "pass --base 0x... (and optionally --arch)"
        )
    else:
        final = _unpack_chain(path, workdir, caps, manifest.formats, manifest.notes)
        entries, total = _enforce_caps(workdir, caps)
        manifest.notes.append(f"extracted entries={entries} bytes={total}")
        if _detect_format(final) == "elf":
            found = detect_elf(final)
            assert found is not None
            manifest.targets.append(LiftTarget(path=str(final), arch=arch or found[0], base=None))
        else:
            # iOS bundles take priority (Payload/*.app with Info.plist metadata)
            bundles = ios_fmt.find_app_bundles(workdir)
            if bundles:
                manifest.formats.append("ios:ipa")
                ios_targets, ios_notes = ios_fmt.select_ios_targets(workdir, MAX_LIFT_TARGETS)
                manifest.notes.extend(ios_notes)
                for t_path, t_arch in ios_targets:
                    manifest.targets.append(LiftTarget(path=str(t_path), arch=t_arch, base=None))
                if not manifest.targets:
                    raise IngestError("no Mach-O binaries found inside the .app bundle(s)")
            else:
                el: list[tuple[str, Path]] = []
                for p in sorted(workdir.rglob("*")):
                    if not p.is_file() or p.is_symlink():
                        continue
                    elf = detect_elf(p)
                    macho = None if elf is not None else ios_fmt.detect_macho(p)
                    if elf is not None or macho is not None:
                        el.append((str(p.relative_to(workdir)), p))
                if el:
                    manifest.formats.append("tree:binaries")
                    for _, p in el[:MAX_LIFT_TARGETS]:
                        elf = detect_elf(p)
                        detected = elf if elf is not None else ios_fmt.detect_macho(p)
                        assert detected is not None
                        manifest.targets.append(
                            LiftTarget(path=str(p), arch=detected[0], base=None)
                        )
                    if len(el) > MAX_LIFT_TARGETS:
                        manifest.notes.append(
                            f"{len(el) - MAX_LIFT_TARGETS} binaries beyond target cap skipped"
                        )
                else:
                    raise IngestError(
                        "no ELF/Mach-O found in the extracted tree; for raw payloads "
                        "pass --base 0x... (and optionally --arch)"
                    )
    return manifest


def choose_pair_targets(old: ImageManifest, new: ImageManifest) -> tuple[LiftTarget, LiftTarget]:
    """v0.1 compares the first target of each side; a note is appended when more exist."""
    if not old.targets or not new.targets:
        raise IngestError("one of the images produced no lift targets")
    if len(old.targets) > 1:
        old.notes.append(f"v0.1 lifts first of {len(old.targets)} targets")
    if len(new.targets) > 1:
        new.notes.append(f"v0.1 lifts first of {len(new.targets)} targets")
    return old.targets[0], new.targets[0]
