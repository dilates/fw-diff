# Operations Runbook

| | |
|---|---|
| **Audience** | maintainers, CI admins, power users |
| **Last updated** | 2026-09-29 |

## 1. Environment

| Requirement | Minimum | Comfortable |
|---|---|---|
| Ghidra | 11.3.x (`GHIDRA_INSTALL_DIR` required) | 11.3.2 |
| Java (for Ghidra) | 21 | 21 LTS |
| RAM | 16 GB | 32 GB (16 MB+ images) |
| Python | 3.11 | 3.12 |
| LLM (optional) | Ollama, 8B-class model | 70B-class if ≥ 64 GB |

Install from source:

```bash
git clone https://github.com/Zlo/fw-diff && cd fw-diff
uv sync && uv run fw-diff --version
uv run fw-diff doctor    # validates Ghidra path, Java, disk space, model reachability
```

## 2. Cache and sessions

- Location: `~/.cache/fw-diff/` (objects/, sessions/, models/)
- Size growth is dominated by lifted images (can be GBs for large firmware)
- `fw-diff cache gc [--older-than 30d] [--dry-run]` — blob GC for unreferenced objects
- `fw-diff sessions list|show <id>|rm <id>`
- **Do not edit session DBs with external tools while a session is open** (single-writer lock;
  ADR-0005)

## 3. Container workers

```bash
docker pull ghcr.io/dilates/fw-diff-worker:11.3.2
fw-diff ci old.bin new.bin --worker-mode docker --policy policy.yaml
```

- Workers get: no network, read-only rootfs, mem/cpu/pids caps, tmpfs scratch (ADR-0008)
- `fw-diff doctor --worker-mode docker` smoke-tests the image pull + a hello-lift run
- Updating Ghidra: build/pull new worker tag, bump `ghidra` pin in repo, CI matrix updates in
  the same PR (cache keys change → plan for cold cache on next runs)

## 4. Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `GhidraAnalysisError: OOM` | JVM heap too small for image | `--jvm-heap 8g` (or larger); worker cap accordingly |
| ingest exits 2, "unsupported container format" | nested/obscure packaging | add ingestor or extract manually; file an issue with the manifest |
| S3 produces no matches, all `ambiguous` | embedding model missing/wrong version | `fw-diff models list`; `doctor` re-downloads pinned model |
| Explainer section absent | provider unreachable or `--llm off` | `fw-diff explain --llm ollama` ; check `ollama list` |
| `facts.json` differs between runs | non-reproducibility — treat as P1 bug | attach both sessions: `fw-diff sessions show <id> --debug-digest` |
| unsquashfs: permission bits chaos | extraction umask | fixed caps enforce umask 022; check `--caps` overrides |

## 5. Metrics and logging

- Structured logs (JSON) to stderr; `--log-level debug` includes per-stage timings
- Session log is stored in the session dir (survives re-runs)
- Key counters to watch in CI: `lift_gaps`, `ambiguous`, `dropped_claims` (LLM), stage
  durations vs perf budget

## 6. Escalation path (maintainers)

1. Reproducibility bug → P1, block release, file with `--debug-digest` output
2. Crash on untrusted input → P1, check THREAT_MODEL §3.1 exposure, coordinate fix per
   SECURITY.md if attacker-triggerable
3. Match regression on corpus → P2, attach corpus job link to PR/issue
4. Everything else → normal issue triage (CONTRIBUTING labels)