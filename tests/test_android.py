"""Android sparse conversion + ELF carving tests."""

from __future__ import annotations

import struct

from fw_diff.android import carve_elfs, detect_sparse, sparse_to_raw


def _sparse(chunks: list[tuple[int, bytes | int]], blk_sz: int = 4096) -> bytes:
    """Build a sparse image from (tag, payload) chunk specs."""
    body = b""
    total_blks = 0
    for tag, payload in chunks:
        if tag == 0xCAC1:  # RAW
            n = len(payload) // blk_sz
            total_blks += n
            body += struct.pack("<HHII", tag, 0, n, 12 + len(payload)) + payload
        elif tag == 0xCAC2:  # FILL
            total_blks += 1
            body += struct.pack("<HHII", tag, 0, 1, 16) + struct.pack("<I", payload)
        elif tag == 0xCAC3:  # DONTCARE
            total_blks += 1
            body += struct.pack("<HHII", tag, 0, 1, 12)
    header = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk_sz, total_blks, len(chunks), 0)
    return header + body


def test_detect_sparse() -> None:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "system.img"
        p.write_bytes(_sparse([(0xCAC3, None)]))
        assert detect_sparse(p) is True
        p.write_bytes(b"\x00" * 64)
        assert detect_sparse(p) is False


def test_sparse_roundtrip() -> None:
    blk = b"\x11\x22\x33\x44" * 1024  # 4096 bytes
    chunks = [
        (0xCAC1, blk),
        (0xCAC2, 0xDEADBEEF),
        (0xCAC3, None),
        (0xCAC1, blk),
    ]
    raw = sparse_to_raw_raw(chunks)
    assert raw == (blk + (0xDEADBEEF).to_bytes(4, "little") * 1024 + b"\x00" * 4096 + blk)


def sparse_to_raw_raw(chunks: list[tuple[int, bytes | int]]) -> bytes:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "img"
        p.write_bytes(_sparse(chunks))
        return sparse_to_raw(p)


def test_carve_elfs_from_raw() -> None:
    import tempfile
    from pathlib import Path

    from fw_diff.ingest import detect_elf

    if not __import__("shutil").which("gcc"):
        import pytest

        pytest.skip("gcc not available")
    import subprocess

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "t.c"
        src.write_text("int main(void){return 42;}\n")
        exe = Path(tmp) / "t"
        subprocess.run(["gcc", "-O0", str(src), "-o", str(exe)], check=True)
        blob = exe.read_bytes()
        raw = b"\x00" * 8192 + blob + b"\xff" * 4096 + blob
        carved = carve_elfs(raw)
        assert len(carved) == 2
        assert carved[0][0] == 8192
        for _off, data in carved:
            assert data.startswith(b"\x7fELF")
            assert detect_elf_bytes(data) is not None
        _ = detect_elf


def detect_elf_bytes(data: bytes):
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "x"
        p.write_bytes(data)
        from fw_diff.ingest import detect_elf

        return detect_elf(p)
