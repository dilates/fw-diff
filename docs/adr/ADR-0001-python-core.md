# ADR-0001: Python-first core, Rust as optional acceleration

**Status:** Accepted · 2026-09-29 · Deciders: architecture review

## Context

fw-diff is heuristic-heavy (normalization, matching, classification) with modest compute
(hash + simhash + ONNX embed). Candidate languages: Python, Rust, Go, Java (native to Ghidra).

## Decision

Implement the core in **Python 3.11+**. Performance-critical inner loops (hashing, simhash,
greedy bipartite matching) may be extracted into a Rust crate (`fwdiff-match`) **only if**
profiling against the perf budget (ARCHITECTURE §7) fails, and exposed via PyO3 behind the
same internal API.

## Consequences

- Fast iteration on the risky parts (heuristics); excellent Ghidra/binwalk/magic ecosystem;
  PyGhidra integration is native.
- Slowly-typed risk mitigated by: full `mypy --strict`, ruff, >90% coverage on the
  deterministic core, type-checked plugin protocol (plugin-api).
- We accept GIL limits; parallelism is process-based (`concurrent.futures`), which also
  isolates worker crashes.
- Java was rejected despite Ghidra nativeness: iteration speed on the experiment-heavy
  matching stages matters more, and PyGhidra keeps us close to the JVM without writing it.

## Alternatives

- **All-Rust:** fastest, best binary distribution — but Ghidra scripting, magic/unpack
  libraries, and LLM clients are all Python-first; iteration cost on heuristics too high.
- **All-Java:** aligns with Ghidra internals; poor story for report tooling and packaging.
