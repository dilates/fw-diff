# Glossary

| Term | Meaning |
|---|---|
| **FunctionIR** | Our per-function intermediate representation extracted from Ghidra (ARCHITECTURE §3.1) |
| **Normalization** | Canonical rewriting of decompiled pseudocode so builds are comparable (pipeline-spec §3) |
| **`h_exact` / `h_struct`** | Normalized-text hashes with constants preserved / wildcarded |
| **S0–S4** | Matching stages: anchors → exact hash → structural → embedding → manual (pipeline-spec §4) |
| **MatchSet** | Correspondences between old/new functions with method + confidence |
| **ChangeFacts** | Deterministic diff output: edits + classifier tags + evidence; source of truth |
| **Edit** | Clustered set of AST edit ops forming one human-meaningful change |
| **Classifier** | Deterministic rule mapping edits → tags (e.g. `bound_change`) |
| **Security relevance** | Rubric score (high/med/low) attached to a change, with component breakdown |
| **Hypothesis** | Possible interpretation (e.g. `CWE-190?`) — never a verdict |
| **Explain** | LLM annotation layer; must cite fact IDs; validated and drop-on-fail |
| **Evidence row** | Pointer to concrete data (edit, callgraph path, import, string) backing a claim |
| **Lift gap** | Region Ghidra could not analyze; rendered honestly in reports |
| **Ambiguous pair** | S3 candidates below margin rule threshold; left for human mapping |
| **Session** | One comparison run: store dir + SQLite DB + blob references |
| **Blob store** | Content-addressed (sha256) artifact storage; dedupes across sessions |
| **Worker** | Sandboxed container running lift/unpack on untrusted input |
| **Policy** | YAML rule set consumed by `fw-diff ci` to gate on classifier tags |
| **Corpus case** | Synthetic firmware pair built from our source with known ground truth |
| **Eval** | Rubric-scored measurement of explainer factuality/usefulness |
| **Prompt version (`pv*`)** | Hash-tracked revision of the explain prompt, recorded in facts |
| **PyGhidra** | Ghidra's official Python integration; our in-process lift path |