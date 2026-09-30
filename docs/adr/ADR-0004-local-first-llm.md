# ADR-0004: Local-first LLM providers; remote endpoints are opt-in

**Status:** Accepted · 2026-09-29

## Context

Firmware images and their diffs are frequently confidential (vendor NDAs, embargoed devices,
 unreleased builds). Sending them to a cloud LLM is a non-starter for a large part of the
audience. Yet explanation quality depends on model capability.

## Decision

**Default provider: local Ollama** (OpenAI-compatible). Also first-class: llama.cpp server,
vLLM, and any OpenAI-compatible endpoint — user must explicitly pass `--llm-url` to leave the
machine. Zero default network egress; tests must pass with all network stubbed (offline mode
is a supported configuration, not a degraded one). Every report records the provider, model
ID, and prompt version; remote providers emit a visible banner into HTML/MD reports.

## Consequences

- Model tier defaults are modest (e.g., llama3.1:8b-class); the eval harness (testing-strategy
  §5) keeps us honest about which model sizes meet the factuality bar.
- No telemetry, no API keys in core; a "bring your own key" remote path exists but is opt-in
  and loudly marked.
- Explainer performance depends on local hardware; docs publish minimum viable hardware
  (≥ 16 GB RAM for 8B-class models) and the tool degrades to `--llm off` gracefully.

## Alternatives

- **Cloud-first with privacy tier:** maximizes out-of-box quality, betrays the core audience
  (RE/security), adds compliance surface. Rejected.
- **No LLM:** see ADR-0003 alternative — kept as the always-available mode.
