# ADR-0006: Multi-stage matcher on decompiled text; not Ghidra VT, not embeddings-only

**Status:** Accepted · 2026-09-29

## Context

Function matching across builds is the precision/recall heart of the product. Options:
(a) run Ghidra's Version Tracking headless, (b) single embedding-similarity stage,
(c) BinDiff-style assembly-graph matching, (d) our own multi-stage matcher over normalized
*decompiled* text.

## Decision

**Own multi-stage matcher** (pipeline-spec §4): S0 anchors → S1 exact normalized hash →
S2 structural simhash with call-graph-anchored iterative voting → S3 embeddings with an
ambiguity margin rule → S4 manual overrides. Matching operates on normalized decompilation
(ADR-0007), not assembly.

## Rationale (why not the others)

- **Ghidra VT:** closest prior art; but it is designed around interactive GUI confirmation,
  its algorithms operate at assembly level (sensitive to recompilation shifts), and our corpus
  showed it underperforms on `h_struct`-style textual similarity for `-O2`-vs-`-Os` rebuilds.
  We borrow its symmetric-hash/histogram concepts and reimplement them on our normalized IR.
- **Embeddings-only:** attractive simplicity, but (1) embedding models drift → reproducibility
  risk in the deterministic core (mitigated: model pinned in facts, but still slow/expensive
  at 10k functions), (2) no call-graph evidence, so precision on similar boilerplate is poor,
  (3) the ambiguity margin problem: a raw nearest-neighbor match lies with high confidence.
  Embeddings remain S3, for what hash stages cannot reach.
- **Assembly-graph matching (BinDiff-style):** strongest math, but heavy to implement and
  poor on RISC (straight-line, fewer basic blocks); decompiled-text structure is a better
  signal-to-effort trade for our firmware-first audience.

## Consequences

- Stages are individually testable against the corpus with per-stage precision/recall gates.
- Confidence values are calibrated per stage (corpus regression run required when tuning);
  calibration tables live in `fw_diff/match/config.toml` and are versioned.
- Expected cost: S2's iterative voting is the slowest stage; bounded by 6 rounds and
  candidate pruning (only S1-neighborhood + S0 pins + import-signature candidates).