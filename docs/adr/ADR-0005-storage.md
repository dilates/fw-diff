# ADR-0005: SQLite + content-addressed object store; no server dependency

**Status:** Accepted · 2026-09-29

## Context

Sessions hold: manifests, per-image `FunctionIR` bundles (10k+ functions), match rows, edit
rows, and reports — potentially gigabytes across many sessions. Options: plain JSON files,
SQLite, DuckDB, Postgres, object-store service.

## Decision

**SQLite** (WAL mode) per session for relational/queryable state + a **content-addressed blob
store** (`sha256`-addressed files under `~/.cache/fw-diff/objects/`) for large artifacts
(images, IR bundles, reports). Blobs dedupe naturally across sessions sharing an image.
No external services.

## Conclusions / Consequences

- Zero-ops: `pip install` and it works; `fw-diff cache gc` reclaims space; sessions are
  portable by copying a directory (blob store + DB are self-contained).
- Concurrency: single-writer per session (a file lock); workers are stateless and hand results
  back through the CLI process. We do not support concurrent writers on one session — instead
  we make sessions cheap.
- DuckDB rejected (analytics-first, weak row-upsert story for our access pattern);
  Postgres rejected (ops cost unjustified for a CLI tool; re-evaluate only if a server product
  emerges — see PRODUCT_SPEC §7);
- JSON-file-only rejected: query speed on 10k-row match tables and atomicity under
  crash-during-write.
