# Corpus

Synthetic firmware test cases (ADR-0009): **we write the source, we build both variants, we
know the ground truth.** No binaries are ever committed — CI runs cases in **IR-fixture
mode** (committed lifted IR in `src/fw_diff/demo/`, which *is* the lifted IR of the
`bounds-fix` case below); full compile+lift mode runs locally/at release.

## Layout

```
tests/corpus/<case>/
├── source/v1.c        # "before" source
├── source/v2.c        # "after" source (the scripted change)
├── variants.yaml      # arch, toolchain, flags per variant
├── Makefile           # builds v1.bin / v2.bin with pinned toolchains (Docker)
└── expect.json        # expected match/classifier/relevance facts
```

## Cases

| case | change scripted in v2 | expected tags |
|---|---|---|
| `bounds-fix` | bound clamp inserted before memcpy | `bound_change` (high), `branch_insert` |
| `crypto-swap` | SHA-256 K[0] constant replaced | `constant_change`, `crypto_constant_change` (medium) |
| `version-bump` | version string changed in main | `string_change` (low) |

## Running

- CI (fast, deterministic): `pytest -m corpus` — asserts `expect.json` against the IR
  fixtures (no toolchains, no Ghidra).
- Full (local, needs cross toolchains + Ghidra + Docker):
  `make -C tests/corpus/bounds-fix && fw-diff ci tests/corpus/bounds-fix/v1.bin
  tests/corpus/bounds-fix/v2.bin --policy tests/corpus/bounds-fix/policy.yaml`

Threshold changes (τ, δ, weights) require a full-mode corpus run attached to the PR
(CONTRIBUTING ground rule 4 / pipeline-spec §4 Calibration).