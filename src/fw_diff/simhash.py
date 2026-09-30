"""Simhash over token multisets (pipeline-spec §4 S2)."""

from __future__ import annotations

import hashlib
from collections import Counter


def simhash64(tokens: list[str]) -> int:
    """64-bit simhash; deterministic across runs and platforms."""
    counts = Counter(tokens)
    v = [0] * 64
    for token, weight in counts.items():
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        h = int.from_bytes(digest, "big")
        for i in range(64):
            v[i] += weight if (h >> i) & 1 else -weight
    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= 1 << i
    return out


def simhash_similarity(a: int, b: int) -> float:
    """1 - normalized Hamming distance, in [0, 1]."""
    return 1.0 - (a ^ b).bit_count() / 64.0


def token_simhash_similarity(tokens_a: list[str], tokens_b: list[str]) -> float:
    return simhash_similarity(simhash64(tokens_a), simhash64(tokens_b))
