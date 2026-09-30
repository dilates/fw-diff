# Changelog

All notable changes to fw-diff are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is SemVer
(see [docs/release-process.md](docs/release-process.md)). `facts.json` schema has its own
version field and [compatibility policy](docs/design/report-format.md#compatibility).

## [0.1.0a1] — 2026-09-30

### Added
- Deterministic core: ingest (ELF/raw/tar.gz/cpio/squashfs with resource caps), PyGhidra
  lift (Ghidra 11.3.x via bundled pyghidra), normalization (ADR-0007), multi-stage matcher
  (S0 anchors → S1 exact → S1b unique-struct → S2 call-graph-anchored structural → S3
  optional embeddings → S4 manual map), statement-level delta engine with layout-noise
  filtering, deterministic classifiers + security-relevance rubric.
- `facts.json` schema v1 (byte-reproducible in deterministic mode), `report.md`,
  single-file offline `report.html`.
- LLM explain layer: local-first (Ollama default), evidence-validated claims, drop-on-fail
  guardrails, provenance in facts/reports (ADR-0003/0004).
- CI policy engine (YAML DSL, exit codes 0/1/2); `fw-diff ci`.
- CLI: `explain`, `ci`, `demo` (zero-setup fixture run), `lift`, `doctor`, `sessions`,
  `cache gc`, `plugins list`.
- Project documentation: product spec, architecture, pipeline spec, report format spec,
  plugin API draft, 10 ADRs, threat model, testing strategy, runbook, release process.
- Tests: 79 (unit, reproducibility, CLI e2e, ingest, policy, explainer guardrails, corpus
  fixture mode, real-Ghidra integration on `ghidra` marker).
