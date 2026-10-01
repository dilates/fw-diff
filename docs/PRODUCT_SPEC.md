# Product Specification — fw-diff

| | |
|---|---|
| **Status** | Draft v1.0 — reviewed, approved for M1 |
| **Owner** | Product |
| **Last updated** | 2026-09-29 |
| **Related** | [ARCHITECTURE](ARCHITECTURE.md) · [ROADMAP](ROADMAP.md) · ADR-0003, ADR-0010 |

## 1. Problem statement

Firmware is shipped as opaque blobs. When a vendor releases an update, everyone who cares about
that device — security researchers, product-security teams, power users, integrators — asks the
same three questions:

1. **What changed?** (Which functions were added, removed, or modified?)
2. **Why did it change?** (Bug fix? New feature? Crypto swap? New telemetry?)
3. **Is the change dangerous?** (Regression? Removed validation? New attack surface?)

Today, answering these requires BinDiff-style GUI sessions with an expert driving. For
symbol-less ARM/MIPS/RISC-V firmware there is no automated, headless, explainable path at all.
The gap between "byte-level diff" (cmp) and "semantic diff" (BinDiff) stops at *which functions
changed* — it never explains *what the change means*.

## 2. Users and personas

| Persona | What they do with fw-diff | Success looks like |
|---|---|---|
| **Firmware RE analyst** | Diff two vendor releases during triage | Reads the top-10 change summary instead of clicking through 1,900 function pairs |
| **Product-security engineer** | Gates firmware releases in CI before ship | CI fails on `bound_change` in a memcpy caller, passes on version bump |
| **Patch analyst / CERT** | Answers "did vendor X fix CVE-…?" | `fw-diff ci` + policy confirms patched function changed, evidence cited |
| **Embedded hobbyist** | Diffs router/OpenWrt builds after mods | HTML report readable without RE background |

Non-user (explicit): pure x86 PDB-driven desktop-app diffing — better served by BinDiff.
We support it where free (raw PE/ELF), but do not optimize for it.

## 3. Scope

### v1 includes

- CLI tool, single binary feel: `fw-diff {lift,match,delta,explain,report,ci}`
- Inputs (v0.4 AIO): ELF, Mach-O/FAT + iOS .ipa, PE (exe/dll/sys), APK (dex + native
  libs), Switch NRO/NSO, UEFI FV, raw + `--base`, squashfs/cpio/tar/deb/rpm/7z-family,
  Android sparse/UBI, directory trees
- Two-image comparison sessions, cached and resumable
- Deterministic diff facts + three renderers (JSON/Markdown/HTML)
- Local-first LLM annotation (Ollama default, OpenAI-compatible opt-in), fully optional
- CI policy engine with YAML rule DSL and exit-code semantics
- Container worker mode for untrusted input

### v1 explicitly excludes (non-goals)

- **No vulnerability verdicts.** fw-diff emits *hypotheses with evidence* (`bound_change`,
  `CWE-190?`), never "this firmware is vulnerable." Human confirms.
- **No automatic exploitation / dynamic analysis.** Static diff only.
- **No web service / multi-tenant server.** CLI + local report files (see ADR-0010).
- **No source-code diffing** (compiler mapping in `source` mode is a v0.3+ idea, not v1).
- **No decompilation of packed/obfuscated-on-purpose code** — we surface "couldn't lift"
  honestly rather than guessing.

## 4. User stories (v1 acceptance)

1. *As a RE analyst*, I run `fw-diff explain fw_a fw_b` and receive a ranked HTML report in
   under 30 minutes for a pair of 16 MB images on an 8-core machine, **without** writing any
   Ghidra scripts.
2. *As a CI engineer*, I run `fw-diff ci a b --policy policy.yaml` and get exit code 1 with a
   machine-readable reason when a dangerous class of change appears.
3. *As an offline user*, I run the same commands with no network and identical `facts.json`
   output (LLM section clearly marked absent).
4. *As a tool developer*, I can add a custom classifier via the plugin API in <100 lines and
   see it appear in the report.
5. *As a skeptic*, I can click any LLM claim in the HTML report and see the deterministic
   evidence rows that produced it.

## 5. Success metrics

| Metric | Target (v1.0) | Tracked how |
|---|---|---|
| Match precision on corpus (S2/S3 stage) | ≥ 0.90 top-1 | corpus CI, per-case |
| Match recall on corpus | ≥ 0.85 | corpus CI |
| Deterministic reproducibility | 100% byte-identical `facts.json` re-runs | CI job |
| Explainer factuality (eval rubric) | ≥ 0.85, zero fabricated facts tolerated | nightly eval |
| Time-to-report, 16 MB pair, 8 cores | < 30 min | perf budget test |
| CI gate false positives on corpus | 0 on known-good cases | corpus CI |

## 6. Competitive positioning

See the table in the [README](../README.md#why-this-exists). Strategic wedge: **firmware
(native) × headless/CI × explanation**. BinDiff owns x86-with-symbols GUI workflows; we do not
fight there. Ghidra Version Tracking is the closest prior art — it is interactive, GUI-bound,
and explains nothing; our matching stage borrows its concepts (symmetric hashes, histogram
voting) but operates on normalized *decompiled* text, which is more robust to recompilation
than assembly-level similarity.

## 7. Pricing / distribution

Free, open source (BSD-3-Clause). Distribution: PyPI (analysts), GHCR container (CI),
homebrew tap later. No paid tier; a future commercial angle is managed diffing-as-a-service
for vendor patch-monitoring — deliberately not built now (ADR-0010).

## 8. Open questions

- Q1: Should `fw-diff` ship a small embedded embedding model (ONNX, ~30 MB) by default, or
  require Ollama for that stage too? *(Leaning: embed-onnx as default, Ollama for prose.)*
- Q2 (resolved v0.3): timeline mode shipped — `fw-diff timeline v1 v2 v3`.
- Q3 (resolved v0.3): MCP server shipped early — `fw-diff mcp` (read-only tools).

## 9. Decision log (product level)

| Date | Decision | Rationale |
|---|---|---|
| 2026-09-29 | CLI-first, no server in v1 | adoption friction lowest; report files are portable (ADR-0010) |
| 2026-09-29 | Hypotheses-not-verdicts posture | credibility with security audience; avoids liability (ADR-0003) |
| 2026-09-29 | Local LLM default | firmware is confidential; trust is the product (ADR-0004) |
