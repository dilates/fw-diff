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
- [x] S3 embedding stage (ONNX embed model, ambiguity margin rule)
- [x] Raw-firmware packaging: squashfs, cpio, tar.gz unpack with resource caps
- [x] HTML report (side-by-side, evidence links, function graph)
- [x] Corpus CI: 4 cases in IR-fixture mode (bounds-fix, crypto-swap, new-feature,
      dead-function-removed); full compile+lift mode local
- **Exit criteria:** match precision ≥ 0.85 / recall ≥ 0.80 on corpus; report renders offline

### M4 — Explain & gate ✅ (v0.1.0a1)
- [x] LLM provider abstraction (Ollama default, OpenAI-compat opt-in, offline no-op mode)
- [x] Explainer prompt contract + schema validation + evidence citation (guardrails v1)
- [x] CI policy engine: YAML DSL, exit codes, `--fail-on`
- [ ] Packaging: PyPI sdist/wheel, GHCR image, docs site build
- **Release: v0.1.0**

## v0.2 — "Trust me, it's reproducible" ✅ (v0.2.0a1)

- [x] Ghidra headless *container worker* mode (sandboxed untrusted input, ADR-0008)
- [x] Incremental lift cache (blob-level across sessions; Program-DB reuse → v0.3)
- [x] Match tuning: per-arch threshold overrides + S0 name pins (corpus calibration ongoing)
- [x] `report.html` diff navigation (filter by classifier/relevance/text)
- [x] SARIF 2.1 output (security-hypothesis findings → IDE/GitHub code scanning)
- [x] Nightly explainer eval harness with scores (docs/evals/)
- [~] 16 MB pair perf budget: CI-safe fixture smoke shipped; real-image budget tracked
      locally at release

## v0.3 — "Real firmware" ✅ (v0.3.0a1)

- [x] UBI/UBIFS (optional `containers` extra), U-Boot legacy, Android sparse (pure-Python
      sparse->raw + ELF carve); iOS .ipa/Mach-O/FAT support added (v0.3)
- [x] Multi-image timeline mode: `fw-diff timeline v1 v2 v3 v4`
- [ ] Manual mapping overrides (`--map pairs.tsv`) with round-trip through cache
- [x] Plugin API v1 (custom classifiers shipped; renderers/ingestors same contract)
      — stability commitment starts
- [x] Promoted-to-stable classifiers: crypto constant tables (AES S-box etc.), dangerous-API
      proximity scoring (v1 of security relevance rubric)

## v0.4 — "Ecosystem" ✅ (v0.4.0a1)

- [x] AIO binary-format surface: Windows PE, Android APK (dex + native libs), Switch
      NRO/NSO, UEFI FV, .deb/.rpm, 7z-family fallback (MSI/CAB/DMG/pkg/appx),
      directory-tree ingest

- [x] MCP server surface (`fw-diff mcp`: stdio JSON-RPC, read-only sessions/facts tools)
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
