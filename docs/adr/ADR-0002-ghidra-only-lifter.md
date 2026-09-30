# ADR-0002: Ghidra as the sole lifting engine

**Status:** Accepted · 2026-09-29

## Context

We need decompilation for arbitrary Ghidra-supported architectures from symbol-less firmware.
Options: Ghidra, angr (its decompiler), Binary Ninja (commercial), r2/retdec, custom lifter.

## Decision

**Ghidra is the single source of decompilation.** PyGhidra in-process is the default runtime
(Ghidra 11.3.2 tested); headless `analyzeHeadless` inside a sandboxed container is the
`--worker-mode docker` variant (ADR-0008). No other lifter is used in the deterministic
pipeline, ever, because lifter changes would break `facts.json` reproducibility.

## Consequences

- One decompiler dialect to normalize (pipeline-spec §3) — keeps the normalization spec small
  and testable.
- Multi-arch support inherits Ghidra's processor modules for free.
- Ghidra versions are pinned per session and recorded in facts (`tool.ghidra`); the cache key
  includes the version, so upgrades never silently corrupt old sessions.
- Binary Ninja's API ergonomics are attractive but its license is incompatible with an OSS
  default pipeline; a BINJA renderer/ingestor remains possible later as a plugin, out of core.
- angr rejected: its decompiler output differs in structure and its arch coverage of
  obscure embedded cores is weaker than Ghidra's; retdec/r2 rejected: output quality and
  maintenance risk for MIPS/RISC-V corner cases.

## Notes

Ghidra's own Version Tracking engine was considered for the matching stage; see ADR-0006 for
why we borrow its ideas but implement our own matcher.
