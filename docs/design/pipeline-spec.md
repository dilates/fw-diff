# Pipeline Specification

| | |
|---|---|
| **Status** | Approved for M1–M4; §3 normalization is normative |
| **Owner** | Engineering |
| **Last updated** | 2026-09-29 |

This is the deep spec of the six pipeline stages: ingest → lift → normalize → match → delta →
explain. The normalization and matching sections are **normative**: implementations must match
them, and corpus tests enforce that. Everything else is guidance until exercised.

---

## 1. Ingest

### 1.1 Inputs (v1)

| Format | Detection | Handling |
|---|---|---|
| ELF (any arch Ghidra supports) | magic + header parse | direct lift, section layout preserved |
| Raw flat binary | fallback | requires `--base 0x…`; optional `--arch` (else heuristics) |
| squashfs | magic `hsqs`/`sqsh` | `unsquashfs` to tree, pick kernel/uImage binaries, lift each |
| cpio / cpio.gz | magic | unpack to tree |
| tar/tar.gz sysupgrade bundles | tar parse | unpack, recurse (depth ≤ 3) |
| U-Boot legacy/uImage | magic | extract payload |

### 1.2 Resource caps (normative)

Max unpacked size 2 GB total, max tree depth 8, max entries 100k, symlink traversal
prohibited, no network, per-stage wall-clock timeout (default 30 min). Caps are
configurable but never disableable in `ci` mode. Rationale: THREAT_MODEL §3.1.

### 1.3 Manifest

Every ingested image produces a manifest: sha256, detected formats (chained), chosen lift
targets (file, arch, base), and decisions log. The manifest is stored and rendered in reports
so humans can audit auto-detection.

### 1.4 Arch detection heuristics (raw binaries)

ELF header when present. Otherwise, in order: U-Boot header fields → string evidence
(`arch/arm/`, `.rodata` kernel banners) → Ghidra auto-detect on candidate archs ranked by
length of the longest valid disassembly run (lift short prefix per candidate, pick winner).
Detection result is displayed and overrideable; it is never silently trusted for raw images.

---

## 2. Lift (Ghidra)

### 2.1 Engine

Ghidra 11.3+ via **PyGhidra in-process** by default (ADR-0002). Headless `analyzeHeadless` in
a container is the `--worker-mode docker` variant. Both run identical analysis options:

- Decompiler: `decompile` action, `decompileParameterId` analysis on
- Struct/function ID: default analyzers + `Demangler*` off (noise for firmware)
- Version-tracking-specific analyzers stay off; we implement matching ourselves

### 2.2 What we extract (per function)

Everything in `FunctionIR` (ARCHITECTURE §3.1): name/aliases, address/size, params, raw +
normalized pseudocode, callgraph edges (internal + import calls), string references,
numeric constant set, and (S3) embedding. Import calls are resolved to `IMPORT_<name>` nodes
so cross-build import renames don't break matching.

### 2.3 Cache key

`sha256(image bytes) + {arch, base, ghidra_version, analyzer_profile}` → blob address. Any
change in the tuple invalidates. Program DBs are additionally cached in Ghidra's own format so
re-analysis of the same image with a new *decompiler* setting can skip analysis.

### 2.4 Honest failure

Unlifted regions (unpackable, unanalyzable) are recorded as `LiftGap` entries with byte ranges
and render in reports as explicit "we could not see here" bands. Never silently skipped.

---

## 3. Normalization (normative)

Goal: make decompiled pseudocode comparable across compiler versions, flags, and symbol-free
builds, without destroying the signals that matter (constants, structure, call shapes).

### 3.1 Identifier canonicalization

| Source token | Canonical form |
|---|---|
| Ghidra function names (`FUN_4001a4f0`) | `f<ordinal>` by first-appearance order within the function's *text only* (cross-function names normalized per-image, globally consistent within a session) |
| Local variables | `l1..ln` in order of first appearance |
| Parameters | `p1..pn` |
| Global data labels | `g1..gn` per-image, ordered by address |
| Registers (implicit) | left as emitted |
| Struct field names (recovered) | `fld<ordinal>` of the recovered layout |

### 3.2 Constant handling — two hash levels

Additionally (v0.1 implementation note): the **struct view also neutralizes cross-image
identifiers** — `f<ord>` → `FCALL`, `g<ord>` → `GDATA` — because address-ordered ordinals
are image-layout artifacts and shift across rebuilds. The exact view keeps them (genuinely
exact comparisons). Matcher call-signatures stay discriminating because they canonicalize
through already-matched pairs, not through text.

- **`h_exact`**: normalized text with constants **preserved**. Matches only truly identical
  decompilations.
- **`h_struct`**: numeric constants replaced by `C<int-width>` tokens (so `0x40` and `0x80`
  compare equal), but **constant *presence* and *count* preserved**. String literals replaced
  by `S<len>`.

Rationale: patch releases legitimately change magic numbers and lengths; `h_struct` catches
"same code, tuned constants," while `h_exact` catches "identical code." Both feed matching and
the `constant_change` classifier.

### 3.3 Structural noise rules

- Casts dropped; parentheses re-normalized; whitespace collapsed
- Implicit `undefined*` pointer arithmetic re-rendered in canonical byte-offset form
- Condition formatting normalized (`if (a) if (b)` vs `if (a && b)` NOT merged — Ghidra is
  consistent enough; merging would lose branch evidence)
- `switch` tables rendered in canonical case-order
- Comma-operators split into statement sequences

### 3.4 Embedding text

The embedding input for S3 is `pseudocode_norm` with identifiers additionally replaced by
their *roles* (`f* → FUNC`, `l* → VAR`) to prevent memorizing ordinal alignments. Constants
kept (semantic signal).

---

## 4. Matching (normative stages)

### S0 — Global anchors (cheap, always run)

Version/build strings, build IDs, symbol tables, entry points, and interrupt/exception vector
tables are matched first and pinned. They (a) seed S2, (b) provide the "same program?"
sanity check, and (c) anchor *named* functions that S1/S3 might miss.

### S1 — Exact hash

Match identical `h_exact`. Expected to cover 60–90% of functions on a small patch release.

### S2 — Structural, call-graph anchored

For remaining functions:

1. Build candidate pairs from S1-matched neighborhoods (callers/callees of matches), S0 pins,
   and import-call signatures.
2. Score candidates: weighted combination of `h_struct` similarity (simhash over token
   multiset), call-edge signature overlap (which normalized callees each side calls), and
   parameter/string constant overlap.
3. Iterative refinement: accepted matches propagate confidence along call edges
   (Ghidra-VT-style voting, but on decompiled text). Max 6 rounds.
4. Accept above threshold τ (default 0.80); emit `match_method=struct_hash` with confidence.

### S3 — Embedding, ambiguity-guarded (optional; ships in v0.2)

Requires the `embed` extra + a model; when unavailable the stage is skipped and reported in
`summary.skipped_stages` (never silently). Remaining candidates embedded (ONNX default
model; document exact model+version in `facts.json`). Cosine similarity, greedy bipartite acceptance with the **ambiguity margin
rule**: accept only if `sim(top1) ≥ 0.82 AND sim(top1) − sim(top2) ≥ 0.08`. Ambiguous pairs
are *reported*, not matched.

### S4 — Manual mapping

`--map pairs.tsv` (`old_id<TAB>new_id<TAB>reason`) forces matches; forced matches are labeled
`match_method=manual` and visually distinct in reports. Maps are cached per session.

### Calibration

Thresholds ship as defaults but are **calibrated against the corpus** (testing-strategy §4);
per-arch overrides live in `fw_diff/match/config.toml`. Changing a threshold requires a corpus
regression run attached to the PR.

---

## 5. Delta engine

### 5.1 Scope

Only matched pairs whose `h_exact` differ go to the delta stage (plus added/removed sets from
the match stage).

### 5.2 Statement diff (v0.1) / AST diff (v0.2)

**v0.1 (shipped):** Ghidra emits roughly one statement per line, so lines of the normalized
exact text are the diff unit (difflib opcodes), clustered into edits. Updates that differ
only in `f<ord>`/`g<ord>` identifiers are dropped as layout noise before classification —
a pair whose edits all vanish this way is not a change.

**v0.2 (planned, ROADMAP):** GumTree-style AST diff on the decompiler's own AST for
sub-statement precision; same edit-op vocabulary (`insert`, `delete`, `move`, `update`).

Inlining flips (callee body appears inside caller between builds) are detected and tagged
`inline_shift` — reported as a match-quality caveat, not a code change.

### 5.3 Edit clustering

Adjacent/related edit ops cluster into **edits** (e.g., "bound check inserted" = 1 insert of a
comparison + 1 insert of a guard jump). Clusters are the unit reports and classifiers work on.

### 5.4 Classifiers (v1 set, detection rules)

| Tag | Detection rule (deterministic) |
|---|---|
| `constant_change` | `update` on a constant token within a matched node |
| `crypto_constant_change` | constant ∈ known crypto constant table (AES S-box, MD5/SHA init vectors, DES PC tables, etc.) |
| `bound_change` | inserted comparison against a constant that dominates a call to a memory op (`memcpy`, `strcpy`, `sprintf`, `memmove`, `bcopy`) in the same cluster |
| `branch_insert` / `branch_remove` | insert/delete of conditional node |
| `call_target_change` | `update` on a callee expression, incl. import name change |
| `signature_change` | parameter count/type change in pair |
| `string_change` | `update`/insert/delete of a string literal node |
| `auth_surface_change` | function is reachable from a detected network/UART input path AND has an edit (reachability via callgraph from `IMPORT_recv*`/`read`/`socket*` roots) |

### 5.5 Security relevance rubric (v1)

Score = weighted sum: dangerous-API proximity (0–3), auth-surface reachability (0/2),
crypto-constant involvement (0/2), bound/pointer edit class (0/3). Mapped to `high/medium/low`
and attached to facts. Rubric thresholds are corpus-calibrated; every score carries its
component breakdown as evidence.

---

## 6. Explainer (LLM)

### 6.1 Input contract

The LLM receives, per batch: session metadata, 3–8 changes, each with (a) classifier tags and
evidence rows, (b) trimmed old/new normalized pseudocode windows (≤ 60 lines each, hot region
centered), (c) affected caller/callee name lists, (d) strings/constants of interest. **It does
not receive raw session state, file paths, or ability to call tools.**

### 6.2 Prompt contract

System prompt (versioned in-repo, hashed into `facts.json`): explain each change in ≤ 3
sentences, plain technical English; for each sentence attach `evidence` referencing provided
fact IDs; output strictly per the JSON schema; if evidence is insufficient, say so and mark
`confidence: low`. Firmware-internal strings appear inside data fences; the model is
instructed to treat them as data (THREAT_MODEL §3.3).

### 6.3 Validation (normative)

Output is parsed against a JSON schema; any claim whose `evidence` IDs don't resolve to
provided facts is **dropped**; per-change narrative is dropped entirely if > 50% of its claims
fail. Dropped counts are recorded. `facts.json` marks the explain section
`"provenance": {"model": "...", "prompt_version": "...", "dropped_claims": N}`.

### 6.4 Cost control

Batching (3–8 changes/request), hard token budget per change, single-pass (no agentic loop —
deliberate, ADR-0003), default temperature 0.2, seed pinned when provider supports it.
`--llm off` is always available and produces identical non-explain sections.
