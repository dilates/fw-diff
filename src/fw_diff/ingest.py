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
from . import formats as fmt_mod
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
    if fmt_mod.detect_pe(path) is not None:
        return "pe"
    if fmt_mod.detect_dex(path):
        return "dex"
    if fmt_mod.detect_switch(path) is not None:
        return "switch"
    if fmt_mod.detect_uefi_fv(path):
        return "uefi"
    if fmt_mod.is_ar(path):
        return "ar"
    if fmt_mod.is_7z(path) or fmt_mod.is_msi(path) or fmt_mod.is_cab(path):
        return "sevenz"
    if fmt_mod.looks_like_dmg(path) or _ext(path) in (".pkg", ".rpm", ".deb", ".apk"):
        return _ext(path).lstrip(".")
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
        if fmt in (None, "elf", "macho", "pe", "dex", "switch", "uefi"):
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
        if fmt in ("deb", "ar"):
            out = workdir / f"deb_out_{len(formats)}"
            out.mkdir(parents=True, exist_ok=True)
            notes.extend(fmt_mod.deb_extract(cur, out, caps.timeout_s))
            formats.append("ar")
            inner = _first_inner_archive(out) or (
                _scan_carvable_dir(out) if _has_binaries(out) else None
            )
            if inner is None:
                formats.append("tree")
                return out
            cur = inner
            continue
        if fmt == "rpm":
            out = workdir / f"rpm_out_{len(formats)}"
            out.mkdir(parents=True, exist_ok=True)
            if not fmt_mod.rpm_to_cpio(cur, out, caps.timeout_s):
                raise IngestError(
                    ".rpm detected but rpm2cpio/cpio are not installed — install them "
                    "(or repackage via 7z)"
                )
            notes.append("rpm payload extracted via rpm2cpio")
            formats.append("tree")
            return out
        if fmt == "sevenz" or fmt in ("dmg", "pkg", "msi", "cab", "7z"):
            out = workdir / f"7z_out_{len(formats)}"
            out.mkdir(parents=True, exist_ok=True)
            if not fmt_mod.sevenz_available():
                raise IngestError(
                    f"{fmt} detected but no 7z tool installed (7zz/7za/7z) — install "
                    "one to unpack this format"
                )
            fmt_mod.sevenz_extract(cur, out, caps.timeout_s)
            notes.append(f"{fmt} extracted via 7z")
            formats.append("tree")
            return out
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


def _ext(path: Path) -> str:
    return path.suffix.lower()


def _has_binaries(tree: Path) -> bool:
    for p in sorted(tree.rglob("*")):
        if p.is_file() and not p.is_symlink() and fmt_mod.detect_binary(p):
            return True
    return False


def _scan_carvable_dir(tree: Path) -> Path | None:
    return tree if _has_binaries(tree) else None


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
    if path.is_dir():
        return _ingest_dir(path, workdir, caps)
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
    elif fmt in ("pe", "dex", "switch", "uefi") and base is None:
        detected = fmt_mod.detect_binary(path)
        assert detected is not None
        manifest.formats.append(fmt)
        manifest.targets.append(LiftTarget(path=str(path), arch=arch or detected, base=None))
        if fmt == "uefi":
            manifest.notes.append("UEFI firmware volume: Ghidra parses FV contents")
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
            selected = _select_tree_targets(workdir, MAX_LIFT_TARGETS, manifest)
            if not selected:
                raise IngestError(
                    "no lift-able binaries (ELF/Mach-O/PE/DEX) found in the extracted "
                    "tree; for raw payloads pass --base 0x... (and optionally --arch)"
                )
            manifest.targets.extend(selected)
    return manifest


def _select_tree_targets(
    workdir: Path, max_targets: int, manifest: ImageManifest
) -> list[LiftTarget]:
    """Target selection for extracted trees: iOS .app, Android APK libs/dex, then any
    lift-able binary (ELF/Mach-O/PE/DEX/Switch/UEFI) — capped, sorted, deterministic."""
    # iOS bundles take priority (Payload/*.app with Info.plist metadata)
    bundles = ios_fmt.find_app_bundles(workdir)
    if bundles:
        manifest.formats.append("ios:ipa")
        ios_targets, ios_notes = ios_fmt.select_ios_targets(workdir, max_targets)
        manifest.notes.extend(ios_notes)
        return [
            LiftTarget(path=str(t_path), arch=t_arch, base=None) for t_path, t_arch in ios_targets
        ]

    # Android APK layout: lib/<abi>/*.so (ELF) + classes*.dex
    apk_markers = list(workdir.rglob("AndroidManifest.xml")) or list(workdir.rglob("classes.dex"))
    if apk_markers:
        manifest.formats.append("android:apk")
        targets: list[LiftTarget] = []
        abis = sorted(
            {
                p.parent.name
                for p in workdir.rglob("lib/*/*.so")
                if p.is_file() and not p.is_symlink()
            }
        )
        if abis:
            manifest.notes.append(f"apk native ABIs: {', '.join(abis)}")
        dexes = [
            p for p in sorted(workdir.rglob("classes*.dex")) if p.is_file() and not p.is_symlink()
        ]
        libs = [
            p for p in sorted(workdir.rglob("lib/*/*.so")) if p.is_file() and not p.is_symlink()
        ]
        if not dexes and not libs:
            manifest.notes.append("apk without native libs or dex targets")
            return []
        for so in libs[:max_targets]:
            detected = fmt_mod.detect_binary(so) or "unknown"
            targets.append(LiftTarget(path=str(so), arch=detected, base=None))
        if len(libs) > max_targets:
            manifest.notes.append(f"{len(libs) - max_targets} native libs beyond cap skipped")
        for dex in dexes[: max(0, max_targets - len(targets))]:
            targets.append(LiftTarget(path=str(dex), arch="dex", base=None))
        manifest.notes.append(f"apk targets: {len(libs)} native libs + {len(dexes)} dex")
        return targets

    # generic tree: any lift-able binary
    targets = []
    skipped = 0
    for p in sorted(workdir.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        binary_arch: str | None = fmt_mod.detect_binary(p)
        if binary_arch is None:
            continue
        if len(targets) >= max_targets:
            skipped += 1
            continue
        targets.append(LiftTarget(path=str(p), arch=binary_arch, base=None))
    if skipped:
        manifest.notes.append(f"{skipped} binaries beyond target cap skipped")
    if targets:
        manifest.formats.append("tree:binaries")
    return targets


def _ingest_dir(path: Path, workdir: Path, caps: ResourceCaps) -> ImageManifest:
    """Directory-tree ingest: .app/.framework bundles, extracted firmware trees, APK dirs."""
    manifest = ImageManifest(path=str(path), sha256="dir")
    manifest.formats.append("dir")
    entries, total = _enforce_caps(path, caps)
    manifest.notes.append(f"tree entries={entries} bytes={total}")
    selected = _select_tree_targets(path, MAX_LIFT_TARGETS, manifest)
    if not selected:
        raise IngestError(
            "directory contains no lift-able binaries (ELF/Mach-O/PE/DEX/Switch/UEFI)"
        )
    manifest.targets.extend(selected)
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
