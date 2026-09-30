# Testing Strategy

| | |
|---|---|
| **Status** | Approved |
| **Owner** | QA / Engineering |

## 1. Principles

1. The deterministic core (ADR-0003) gets **exact assertions**; the LLM layer gets **rubric
   evals**. Never the reverse.
2. Ground truth comes from **synthetic firmware we compile ourselves** (ADR-0009) — we know
   the answer because we wrote the source.
3. Reproducibility is a test: re-running a session must produce byte-identical `facts.json`.

## 2. Test pyramid

| Layer | What | Gate |
|---|---|---|
| Unit | normalization rules, hash functions, classifiers, policy DSL parsing | every PR, `mypy --strict` + >90% line coverage on `fw_diff/{normalize,match,delta,classify}` |
| Golden | fixed IR snapshots → expected facts fragments | every PR |
| Corpus | end-to-end: compile fixture source twice → run pipeline → compare to `expect.json` | every PR |
| Eval (LLM) | explainer factuality/usefulness rubric vs corpus ground truth | nightly + release |
| Perf | budget table from ARCHITECTURE §7 on fixed hardware class | weekly + release |
| Fuzz | image ingest + unpack robustness (crash-only) | nightly, OSS-Fuzz candidate post-v0.2 |
| Worker | docker sandbox lift e2e (ADR-0008) | CI `worker` job (builds image) |
| Perf | fixture pipeline bound | every PR (`pytest -m perf`) |

## 3. Corpus layout

```
tests/corpus/<case>/
├── source/          # C sources for BOTH variants (v1.c, v2.c, shared headers)
├── Makefile         # builds two images; pinned cross-toolchain container
├── variants.yaml    # arch, base, flags, gcc version per variant
└── expect.json      # expected match pairs, classifier tags, relevance classes
```

v1 cases: `bounds-fix`, `version-bump`, `crypto-swap`, `new-feature`,
`dead-function-removed`, `inlining-flip`, `rebuild-flags-change`, `string-table-shift`.

**CI runs cases in IR-fixture mode** (`pytest -m corpus`): expectations are asserted against
committed lifted IR (the `fw_diff.demo` fixture pair *is* the lifted IR of `bounds-fix`) —
no toolchains or Ghidra needed, fully deterministic. **Full mode** (compile + lift via
cross-toolchains + Ghidra) runs locally and at release; see `tests/corpus/README.md`.
Adding a case = source + build recipe + expectations; **blobs are never committed**.

## 4. Matching gates

Per stage and case: precision/recall targets (PRODUCT_SPEC §5). Threshold tuning (τ, δ,
weights) requires: (1) corpus regression run output attached to the PR, (2) no case drops
below target, (3) calibration table diff reviewed by the matching owner. Flaky matching is a
bug: corpus runs are deterministic by construction, so a rerun-varying result fails CI.

## 5. Explainer eval harness

Nightly, not per-PR (cost): every corpus case's *true* change rationale (we wrote it) is the
rubric reference. Graded dimensions:

- **Factuality** (weight 5): zero fabricated facts tolerated — any claim without resolvable
  evidence is an automatic case failure.
- **Correctness of interpretation** (3): does it name the right change class?
- **Usefulness** (2): would an analyst accept the sentence?
- Score ≥ 0.85 required to keep a model on the "recommended models" doc list; scores per
  model published in `docs/evals/` with dates.

## 6. Performance test

Weekly job on the fixed hardware class (8 vCPU / 16 GB): 16 MB corpus pair end-to-end.
Budget from ARCHITECTURE §7; a >10% regression blocks release, tracked as a metric with a
history graph in the docs site.

## 7. Fuzzing

Targets: ingest format detectors, unpackers (fed mutated squashfs/cpio/tar), the pseudocode
normalizer/AST parser (fed mutated Ghidra output). Crash-only assertions (no valid-output
check). Runs on a 2-hour nightly budget; corpus minimization + dedup on failure.

## 8. CI matrix

- Linux × (3.11, 3.12, 3.13) — full suite
- Corpus matrix job (cross-toolchain builds) — full suite, cached toolchains
- Docs job: markdownlint + link check + vale (style) — every PR
- Reproducibility job: run `bounds-fix` twice, byte-compare `facts.json` — every release

## 9. Release gate checklist (automated)

All layers green on release commit · reproducibility job passed · eval scores ≥ targets ·
perf budget met · CHANGELOG updated · schema diff reviewed if `facts.json` changed.