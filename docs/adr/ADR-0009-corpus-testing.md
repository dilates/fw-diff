# ADR-0009: Synthetic corpus for correctness; no public-firmware dependency

**Status:** Accepted · 2026-09-29

## Context

Correctness of match/delta/classify cannot be asserted, only measured. Public firmware
samples are legally murky, huge, and unreproducible; and we need *known ground truth*
(we wrote the source) to score precision/recall and classifier correctness.

## Decision

**The canonical test corpus is synthetic**: small C programs we control, compiled twice
(before/after a scripted change) with pinned cross-toolchains (ARM/MIPS/RISC-V) in Docker,
plus the expected `facts.json` fragments (`expect.json`). Corpus lives in
`tests/corpus/<case>/`, builds reproducibly from source, and CI gates every PR on all cases.
Real-world firmware samples may exist locally for manual testing but are never committed,
never required, and never used in CI.

## Consequences

- Ground truth is exact: we know which functions changed and why; precision/recall are
  meaningful numbers, not vibes.
- Legal cleanliness by construction (our source, our builds, pinned toolchains).
- Risk: synthetic code is too clean — mitigated by adversarial corpus cases (inlining flips,
  `-O2`→`-Os` rebuilds, symbol stripping, string shifts, added padding, different GCC minor
  versions) and by encouraging community-contributed *source+diff* cases (same rules: source
  and build recipe, no blobs).
- Initial cases (v0.1–v0.2): `bounds-fix`, `version-bump`, `crypto-swap`, `new-feature`,
  `dead-function-removed`, `inlining-flip`, `rebuild-flags-change`, `string-table-shift`.

## Alternatives

- **Curated public firmware set:** realistic but legally fragile, unreproducible, and ground
  truth would be manual opinions. Rejected as CI basis; allowed as local smoke material.
- **Property-based fuzzing of images** (for robustness): complementary, not a substitute —
  lives in testing-strategy §7 (crash-only assertions, OSS-Fuzz candidate post-v0.2).