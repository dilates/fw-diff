# ADR-0003: Deterministic facts as source of truth; LLM is annotation-only

**Status:** Accepted · 2026-09-29 · *This is the load-bearing ADR.*

## Context

The product promise is explanation. LLMs are the only practical technology for natural-language
explanation at scale — and they hallucinate, are nondeterministic by default, and are prompt-
injection-prone. A diff tool whose findings cannot be trusted or reproduced is worthless to the
security audience we target.

## Decision

**The pipeline is split into a deterministic core (ingest→lift→match→delta→classifiers) and an
annotation layer (explain).** The core's output — `ChangeFacts` — is the source of truth, is
byte-reproducible, and is what CI gates consume. The LLM receives only bounded, structured
facts plus trimmed code windows, must cite fact IDs for every claim, and its output is
schema-validated with claim dropping (pipeline-spec §6). No agentic loop, no tool use by the
LLM, single pass, pinned prompt version.

## Consequences

- `fw-diff ci` is fully deterministic regardless of LLM availability.
- Reports remain trustworthy with the LLM off; the explain section is a convenience layer,
  visually and structurally marked as model output.
- Hallucination blast radius is capped by evidence validation and per-batch dropping counters.
- We forgo "smart" LLM-assisted matching (e.g., asking the model to match odd functions).
  If we ever want that, it must graduate into a *deterministic* heuristic first (corpus-
  validated) — not live as an LLM call inside the core.

## Alternatives

- **LLM-in-the-loop matching/agentic diffing:** stronger on weird cases, but kills
  reproducibility, CI gating, and auditability. Rejected for v1; revisit never without a
  corpus-proven deterministic equivalent.
- **No LLM at all:** the honest fallback mode — shipped as `--llm off` and the default in CI
  contexts where policy forbids models.
