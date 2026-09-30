"""Android sparse image conversion (ROADMAP v0.3) + raw ELF carving.

Android system/vendor images ship as "sparse" ext4 (magic 0xED26FF3A) to save space.
fw-diff converts them to raw bytes, then carves embedded ELF binaries by magic scan —
the same utility serves generic raw firmware with embedded ELFs.
"""

from __future__ import annotations

import struct
from pathlib import Path

from .log import get_logger

log = get_logger("fw_diff.sparse")

SPARSE_MAGIC = 0xED26FF3A
CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC = 0xCAC4

SPARSE_HEADER_FMT = "<IHHHHIIII"  # magic major minor file_hdr_sz chunk_hdr_sz blk_sz
# total_blks total_chunks checksum
SPARSE_HEADER_SIZE = 28
CHUNK_HEADER_SIZE = 12


def detect_sparse(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(SPARSE_HEADER_SIZE)
    except OSError:
        return False
    if len(head) < SPARSE_HEADER_SIZE:
        return False
    magic = struct.unpack("<I", head[:4])[0]
    return bool(magic == SPARSE_MAGIC)


def sparse_to_raw(path: Path) -> bytes:
    """Materialize an Android sparse image into raw image bytes."""
    data = path.read_bytes()
    (magic, _major, _minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks, _crc) = (
        struct.unpack("<IHHHHIIII", data[:SPARSE_HEADER_SIZE])
    )
    if magic != SPARSE_MAGIC:
        raise ValueError("not an Android sparse image")
    if file_hdr_sz != SPARSE_HEADER_SIZE or chunk_hdr_sz != CHUNK_HEADER_SIZE:
        # tolerate future headers: parse from documented offsets anyway
        log.warning("sparse header sizes differ from spec", extra={"count": 1})
    out = bytearray()
    pos = file_hdr_sz
    seen_chunks = 0
    while pos + CHUNK_HEADER_SIZE <= len(data) and seen_chunks < total_chunks:
        tag, _reserved, _chunk_blks, total_sz = struct.unpack(
            "<HHII", data[pos : pos + CHUNK_HEADER_SIZE]
        )
        body = data[pos + CHUNK_HEADER_SIZE : pos + total_sz]
        if tag == CHUNK_RAW:
            out += body
        elif tag == CHUNK_FILL:
            (fill,) = struct.unpack("<I", body[:4])
            out += fill.to_bytes(4, "little") * (blk_sz // 4)
        elif tag == CHUNK_DONT_CARE:
            out += b"\x00" * blk_sz
        elif tag == CHUNK_CRC:
            pass  # trailing checksum chunk
        else:
            raise ValueError(f"unknown sparse chunk tag {tag:#x} at {pos:#x}")
        pos += total_sz
        seen_chunks += 1
    if len(out) != total_blks * blk_sz:
        log.warning(
            "sparse output size differs from header (decoded %d, header %d)",
            extra={"count": 1},
        )
    return bytes(out)


def carve_elfs(raw: bytes, base_offset: int = 0, max_files: int = 24) -> list[tuple[int, bytes]]:
    """Carve ELF binaries out of a raw image by magic scan; returns (offset, bytes).

    Size is computed from the ELF header (max of section-header table end and the largest
    program segment end, floor 0x1000) — good enough for extraction before Ghidra sees it.
    """
    results: list[tuple[int, bytes]] = []
    start = 0
    while len(results) < max_files:
        hit = raw.find(b"\x7fELF", start)
        if hit < 0:
            break
        start = hit + 4
        if hit + 64 > len(raw):
            break
        ei_class, ei_data = raw[hit + 4], raw[hit + 5]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            continue
        endian = "<" if ei_data == 1 else ">"
        if ei_class == 2:  # 64-bit: e_phoff u64@0x20, e_shoff u64@0x28
            e_phoff = struct.unpack(endian + "Q", raw[hit + 0x20 : hit + 0x28])[0]
            e_phnum = struct.unpack(endian + "H", raw[hit + 0x38 : hit + 0x3A])[0]
            e_shoff = struct.unpack(endian + "Q", raw[hit + 0x28 : hit + 0x30])[0]
            e_shnum = struct.unpack(endian + "H", raw[hit + 0x3C : hit + 0x3E])[0]
            e_shentsize = struct.unpack(endian + "H", raw[hit + 0x3A : hit + 0x3C])[0]
            end = e_shoff + e_shnum * e_shentsize if e_shnum else 0
            for i in range(e_phnum):
                off = e_phoff + i * 56
                if off + 56 > len(raw) - hit:
                    break
                # p_filesz is at offset 0x20 within the entry
                filesz = struct.unpack(endian + "Q", raw[hit + off + 0x20 : hit + off + 0x28])[0]
                end = max(end, e_phoff + off + filesz)
            size = max(end, 0x1000)
        else:  # 32-bit
            e_phoff = struct.unpack(endian + "I", raw[hit + 0x1C : hit + 0x20])[0]
            e_phnum = struct.unpack(endian + "H", raw[hit + 0x2C : hit + 0x2E])[0]
            e_shoff = struct.unpack(endian + "I", raw[hit + 0x20 : hit + 0x24])[0]
            e_shnum = struct.unpack(endian + "H", raw[hit + 0x30 : hit + 0x32])[0]
            e_shentsize = struct.unpack(endian + "H", raw[hit + 0x2E : hit + 0x30])[0]
            end = e_shoff + e_shnum * e_shentsize if e_shnum else 0
            for i in range(e_phnum):
                off = e_phoff + i * 32
                if off + 32 > len(raw) - hit:
                    break
                filesz = struct.unpack(endian + "I", raw[hit + off + 0x10 : hit + off + 0x14])[0]
                end = max(end, e_phoff + off + filesz)
            size = max(end, 0x1000)
        size = min(size, len(raw) - hit)
        if size <= 0:
            continue
        results.append((base_offset + hit, raw[hit : hit + size]))
    return results


def carve_to_files(raw_path: Path, out_dir: Path, max_files: int = 24) -> list[Path]:
    """Carve ELFs from a raw image file into out_dir/carved/; returns written paths."""
    data = raw_path.read_bytes()
    carved = carve_elfs(data)
    out = out_dir / "carved"
    out.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for offset, blob in carved[:max_files]:
        target = out / f"carved_{offset:08x}.elf"
        target.write_bytes(blob)
        paths.append(target)
    return paths
