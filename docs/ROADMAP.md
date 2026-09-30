# Roadmap

Statuses: `planned` → `in-progress` → `done`. Milestones map to 4-sprint releases (~2 weeks
each in team-speak; we are a small team, dates are targets, not promises).

## v0.1 — "Two ELFs and a report" (M1–M4)

The thinnest end-to-end slice that is still genuinely useful: two same-arch ELF files in,
`facts.json` + `report.md` out.

### M1 — Skeleton & lift ✅ (v0.1.0a1)
- [x] CLI skeleton (`fw-diff` entrypoint, `--version`, structured logging)
- [x] Ingest: ELF detection, arch detect from headers, `--base` raw-binary mode
- [x] PyGhidra in-process lift → `FunctionIR` (name, addr, size, pseudocode, callgraph)
- [x] SQLite session store + content-addressed blob cache
- **Exit criteria:** lifting a 4 MB ARM ELF twice hits the cache (second run < 5 s)

### M2 — Match & delta (deterministic core) ✅ (v0.1.0a1)
- [x] Normalization spec v1 implemented (identifier canonicalization, constant buckets)
- [x] S1 exact hash matching
- [x] S2 structural matching (call-graph anchored, decompiled-text simhash)
- [~] Statement-level delta engine + edit clustering (AST diff moved to v0.2)
- [x] Classifiers v1: `constant_change`, `branch_insert`, `call_target_change`,
      `signature_change`, `string_change`, `bound_change`
- [x] Renderers: `facts.json` (schema v1, frozen), `report.md`
- **Exit criteria:** corpus cases `bounds-fix`, `version-bump`, `crypto-swap` reproduce
  expected facts deterministically

### M3 — Quality & formats
- [ ] S3 embedding stage (ONNX embed model, ambiguity margin rule)
- [x] Raw-firmware packaging: squashfs, cpio, tar.gz unpack with resource caps
- [x] HTML report (side-by-side, evidence links, function graph)
- [ ] Corpus CI: 8 fixture cases built from source in cross-toolchain Docker
- **Exit criteria:** match precision ≥ 0.85 / recall ≥ 0.80 on corpus; report renders offline

### M4 — Explain & gate ✅ (v0.1.0a1)
- [x] LLM provider abstraction (Ollama default, OpenAI-compat opt-in, offline no-op mode)
- [x] Explainer prompt contract + schema validation + evidence citation (guardrails v1)
- [x] CI policy engine: YAML DSL, exit codes, `--fail-on`
- [ ] Packaging: PyPI sdist/wheel, GHCR image, docs site build
- **Release: v0.1.0**

## v0.2 — "Trust me, it's reproducible"

- [ ] Ghidra headless *container worker* mode (sandboxed untrusted input, ADR-0008)
- [ ] Incremental lift cache (reuse Program DB across sessions)
- [ ] Match tuning: per-arch weighting, confidence calibration vs corpus
- [ ] `report.html` diff navigation (filter by classifier, arch, confidence)
- [ ] SARIF 2.1 output (security-hypothesis findings → IDE/GitHub code scanning)
- [ ] Nightly explainer eval harness published with scores
- [ ] 16 MB pair perf budget met (tracked metric)

## v0.3 — "Real firmware"

- [ ] UBI/UBIFS, U-Boot legacy images, Android sparse images
- [ ] Multi-image timeline mode: `fw-diff timeline v1 v2 v3 v4`
- [ ] Manual mapping overrides (`--map pairs.tsv`) with round-trip through cache
- [ ] Plugin API v1 (custom classifiers, renderers, ingestors) — stability commitment starts
- [ ] Promoted-to-stable classifiers: crypto constant tables (AES S-box etc.), dangerous-API
      proximity scoring (v1 of security relevance rubric)

## v0.4 — "Ecosystem"

- [ ] MCP server surface (expose sessions/facts to agent tooling)
- [ ] Homebrew formula; Windows support for the analyst CLI (workers stay Linux containers)
- [ ] Community corpus contribution guide + review process
- [ ] i18n-ready report templates

## v1.0 — "Boring, dependable"

- [ ] API stability: `facts.json` v1 + plugin API + CLI contract frozen for 12 months
- [ ] Docs site with versioned docs, 100% CLI flag coverage
- [ ] Two public "proof" case studies (e.g., OpenWrt release pair, known-CVE patch pair)
- [ ] Full threat-model review sign-off, SBOM published, reproducible builds
- [ ] Eval scores ≥ targets from PRODUCT_SPEC §5 sustained for 3 releases

## Beyond 1.0 (parking lot, no commitments)

- Managed patch-monitoring service (watch N vendor feeds, diff automatically)
- Dynamic-analysis correlation (run both images in QEMU, attach behavior deltas)
- Compiler-provenance fingerprinting (which GCC/flags built this?)
- Source-annotated reports when user supplies partial source tree

## Metrics dashboards we keep honest

Corpus precision/recall per stage · reproducibility rate · perf budget · eval factuality ·
crash rate on fuzz corpus (OSS-Fuzz candidate post-v0.2).
