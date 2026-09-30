# ADR-0007: Normalize decompiled pseudocode before any comparison

**Status:** Accepted · 2026-09-29

## Context

Raw Ghidra decompiler output contains Ghidra-invented names (`FUN_4001a4f0`, `DAT_4002ab10`,
`uVar3`) that are functions of *addresses and allocation order* — two builds of the same
source produce textually distant pseudocode purely from placement. Diffing raw text is
meaningless; diffing assembly is too brittle across compiler flags (see ADR-0006).

## Decision

**All comparisons — hashes, simhash, AST diff, embeddings — operate exclusively on normalized
pseudocode** per the normative spec (pipeline-spec §3): identifier canonicalization by
first-appearance ordinals, two-level constant handling (`h_exact` preserves constants,
`h_struct` wildcards them), cast/whitespace/canonical-form rules, and role-masked embedding
text.

## Consequences

- Normalization is the highest-risk code in the project: a normalization bug silently
  poisons every downstream stage. Mitigations: the spec is normative; golden tests pin
  normalization output for reference snippets; every corpus case includes a
  "normalization invariants" assertion (renaming is order-stable; constant bucketing
  lossless at the facts level).
- Original (un-normalized) text is always retained in `FunctionIR` and shown in reports —
  humans read real pseudocode; normalization is for *comparison*, not for display.
- We do NOT attempt identifier recovery/suggestion in v1 (renaming recovered locals to
  guessed names is an explainer-flavored feature and can mislead; future plugin territory).
- Constants are deliberately preserved in `h_exact` even though they are "noise" for
  structure — they are the *signal* for `constant_change`/crypto classifiers, which need the
  un-bucketed values.