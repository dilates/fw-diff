# Changelog

All notable changes to fw-diff are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is SemVer
(see [docs/release-process.md](docs/release-process.md)). `facts.json` schema has its own
version field and [compatibility policy](docs/design/report-format.md#compatibility).

## [0.3.0a1] — 2026-09-30

### Added
- **iOS app support** (.ipa): Mach-O/64-bit + FAT (universal) detection with arm64 slice
  selection, safe zip extraction (traversal-safe, capped), main-executable-first target
  selection over Payload/*.app bundles, Info.plist bundle metadata in manifest notes;
  Ghidra's Mach-O loader does the lifting (aarch64/x86_64/armv7).
- **Android sparse image support**: pure-Python sparse->raw conversion (RAW/FILL/
  DONTCARE chunks) + ELF carving from raw images by magic scan (also serves generic
  raw firmware with embedded ELFs).
- **UBI/UBIFS** extraction via the optional `containers` extra (ubi-reader); honest
  note when unavailable.
- **Timeline mode** (`fw-diff timeline v1 v2 v3`): consecutive-pair diffs + aggregated
  `index.md` per-leg report.
- **Plugin API v1** (stability commitment starts): entrypoint-group discovery, classifier
  plugins integrated after built-ins (pure, evidence-carrying, exception-isolated).
- **MCP server** (`fw-diff mcp`, ROADMAP v0.4 pulled forward): stdio JSON-RPC 2.0 with
  read-only tools (`fw_diff_sessions`, `fw_diff_get_facts`, `fw_diff_get_changes`) for
  agent integration.

## [0.2.0a1] — 2026-09-30

### Added
- **SARIF 2.1 output** (`sarif.json`): high-relevance changes -> warnings with evidence,
  medium -> notes; ready for GitHub code scanning.
- **Docker worker mode** (ADR-0008 realized): `--worker-mode docker|auto` lifts untrusted
  images in a sandboxed container (no network, read-only rootfs, mem/cpu/pids caps,
  tmpfs scratch); `docker/ghidra-worker.Dockerfile` pins Ghidra 11.3.2 + bundled pyghidra;
  results cross the boundary as IR-bundle data. `ci` defaults to `auto`.
- **Blob-level lift cache** across sessions: cache key = file sha256 + lift params;
  payload carries the Ghidra version, so upgrades invalidate automatically.
- **S3 embedding stage** (optional `embed` extra, fastembed/ONNX): ambiguity margin rule
  enforced; model recorded in session config; stage honestly skipped when unavailable.
- **Per-arch threshold overrides** (`Thresholds.for_arch`) + S0 same-name pins (same raw
  Ghidra name = same function by construction).
- **HTML report filters** (vanilla JS, still single-file offline): text search +
  relevance checkboxes.
- **Explainer coverage retry pass**: changes the model skipped in batched requests are
  retried individually; `change_id` key drift tolerated. Eval gate on a 4B local model:
  coverage 1.0, correctness 1.0, 0 factuality violations.
- **Eval harness** (`pytest -m eval`): factuality/correctness/coverage rubric vs local
  Ollama on the corpus pair; scores -> docs/evals/.
- Corpus cases: `crypto-swap`, `new-feature`, `dead-function-removed` (synthetic IR).
- Worker/perf CI jobs; perf smoke test (`pytest -m perf`).

### Fixed
- Worker container: double invocation via ENTRYPOINT, mount-relative io paths,
  JDK discovery in containers (JAVA_HOME_OVERRIDE; full JDK base image).
- `remove_session` GC semantics; HTML table header duplication.

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
