## Summary

<!-- What does this PR change? Link the spec/ADR/issue it implements. -->

## Type

- [ ] feat  [ ] fix  [ ] docs  [ ] test  [ ] perf  [ ] refactor  [ ] chore

## Checklist

- [ ] Spec/docs updated in the same PR if behavior changed (CONTRIBUTING rule 1)
- [ ] ADR created/updated for any architectural decision
- [ ] Tests: fast suite green locally (`pytest -m "not corpus"`)
- [ ] Corpus job green (auto-triggered for match/delta changes)
- [ ] `mypy --strict` + `ruff` pass
- [ ] `facts.json` untouched, or change follows the additive-only policy (report-format)
- [ ] No nondeterminism introduced (no clock/random/unordered iteration in core paths)

## Determinism statement

<!-- If you touched normalize/match/delta: confirm same-input reproducibility. -->