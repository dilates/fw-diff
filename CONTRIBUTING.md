# Contributing to fw-diff

Thanks for your interest. We run this like a product team: **specs first, ADRs for decisions,
corpus-driven tests**. Reading [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/adr/](docs/adr/) before your first PR is the fastest path to a green review.

## Dev setup

```bash
git clone https://github.com/Zlo/fw-diff && cd fw-diff
uv sync --extra dev         # or: python -m venv .venv && pip install -e '.[dev]'
uv pip install 'fw-diff[ghidra]'  # optional: pyghidra (Ghidra 11.3.x pair; see README)
export GHIDRA_INSTALL_DIR=/path/to/ghidra   # 11.3+ required
uv run fw-diff doctor       # verifies environment
uv run pytest -m "not corpus and not ghidra and not eval"   # default suite
uv run pytest -m corpus     # corpus cases in IR-fixture mode (fast, no Ghidra)
uv run pytest -m ghidra     # real-Ghidra integration (needs local Ghidra)
```

## Ground rules

1. **No behavior change without a spec.** Behavior lives in docs/design/*.md; PRs that change
   pipeline behavior must update the spec in the same PR.
2. **Decisions get ADRs.** Anything architectural → `docs/adr/ADR-00XX-…` (template:
   Status/Context/Decision/Consequences/Alternatives). Renumbering is forbidden.
3. **`facts.json` schema is frozen** (v1, additive-only) — schema changes need a new ADR and a
   compat note (report-format §Compatibility).
4. **Determinism is sacred.** No nondeterminism in the core: no dict-order reliance, no
   clock-in-output, no unordered set iteration affecting output. CI enforces byte-identical
   reruns on the reproducibility job.
5. **Classifiers are pure functions.** No I/O, no randomness, no network (plugin-api rules 1–3
   apply to core code too).

## Style

- Format/lint: `ruff format && ruff check` (config in pyproject; line length 100)
- Types: `mypy --strict` passes on everything under `fw_diff/` (plugins get `--strict` too)
- Conventional Commits (`feat:`, `fix:`, `docs:`, `perf:`, `refactor:`, `test:`, `chore:`);
  scope by component, e.g. `fix(match): margin rule off-by-one`
- Public functions get docstrings; internal complexity gets a *why* comment, not a *what*

## PR process

- Small PRs win: one concern per PR; spec/ADR updates may ride along or precede
- CI must be green: lint, types, fast tests, corpus matrix (auto-runs when `fw_diff/match`
  or `fw_diff/delta` changes), docs checks
- Review gates: 1 approval for docs/tests; **2 approvals** for `fw_diff/{match,delta}`,
  worker sandboxing, or anything touching `facts.json` schema
- Component owners (CODEOWNERS) auto-requested:

| Component | Owner role | Files |
|---|---|---|
| matching / delta | Eng lead | `fw_diff/match`, `fw_diff/delta`, docs/design/pipeline-spec.md |
| ghidra integration | Eng (Ghidra) | `fw_diff/ghidra`, worker images |
| explain / LLM | Eng (AI) | `fw_diff/explain`, docs/design/pipeline-spec §6 |
| security | Sec lead | worker sandboxing, THREAT_MODEL, SECURITY |
| reports / schema | Eng | `fw_diff/report`, docs/design/report-format.md |
| docs / DX | Tech writer | README, guides, CONTRIBUTING |

## Issues

Labels: `bug` / `P1..P3` / `area:match` / `area:lift` / `area:llm` / `area:ci` /
`good-first-issue` / `help-wanted`. Spec discussions happen in `RFC` issues; outcomes land as
ADRs, not as issue-thread folklore.

## Good first issues

Look for `good-first-issue`: usually corpus cases, renderer polish, docs, or classifier rules
with existing spec — self-contained and spec-backed.