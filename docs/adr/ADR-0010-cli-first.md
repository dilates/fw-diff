# ADR-0010: CLI-first; no server, no GUI in v1

**Status:** Accepted · 2026-09-29

## Context

Diff results invite three interaction models: files on disk (CLI+reports), a web service
(session browsing, multi-user), and a GUI (interactive function mapping like BinDiff).
Server and GUI are large surface areas that would consume the roadmap.

## Decision

**v1 is a CLI that writes files**: `facts.json`, `report.md`, `report.html` (self-contained,
works from `file://`, no JS beyond a vendored minified viewer). No server, no Electron, no
daemon. Interactive needs are met by (a) report navigation, (b) `--map` manual overrides
round-tripping through the cache, (c) post-1.0: an MCP surface for agent tooling (ROADMAP
v0.4) which gives AI-native interactivity without UI maintenance.

## Consequences

- CI integration is the native mode rather than an afterthought — the actual product wedge.
- A GUI's hardest problem (function-pair confirmation UX) is deferred until the matcher's
  precision makes confirmation rare; building it earlier would bake in wrong interaction
  patterns.
- "Service" ideas (vendor patch monitoring, hosted diffs) are parked with the product team
  (PRODUCT_SPEC §7) and explicitly not built now.
- HTML report must remain single-file and offline — a lint rule checks for external URLs in
  built reports; violation fails the release build.

## Alternatives

- **Web service first:** better demo-ability, worse trust (users upload confidential firmware
  or self-host Django). Rejected for v1.
- **Ghidra plugin UI:** reaches the existing Ghidra audience, but couples our release cadence
  to Ghidra's UI API churn. A thin "open this session in Ghidra" exporter may arrive as a
  plugin (plugin-api) instead of a full GUI.