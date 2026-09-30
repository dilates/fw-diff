# Report Format Specification — `facts.json` v1

| | |
|---|---|
| **Schema version** | `1` (this document) |
| **Status** | Frozen at v0.2 release; additive-only changes until `2` |
| **Owner** | Engineering |

`facts.json` is the deterministic, machine-readable deliverable. It is what CI gates read and
what renderers consume. The LLM explain section is embedded but clearly provenance-marked and
may be absent.

## Deterministic session mode

With `--deterministic` (and always in `ci` mode), `session.id` is derived from the two image
sha256s + tool version, and `session.created_utc` is `null` — making `facts.json`
**byte-identical** across re-runs of identical inputs (the CI reproducibility gate).
Without the flag, `id` is a random uuid and `created_utc` is wall-clock; consumers must
treat both as opaque.

## Compatibility policy

- Schema `1` is additive-only: new optional fields, new enum values appended at the end.
- Consumers must ignore unknown fields; producers must not remove or rename fields within `1`.
- Breaking change → schema version `2`, new file allowed to coexist (`--facts-schema 2`).
- `schema_version` is the first field. CI policies pin the major version they understand.

## Example (annotated, abridged)

```jsonc
{
  "schema_version": 1,
  "tool": {"name": "fw-diff", "version": "0.1.0", "ghidra": "11.3.2"},
  "session": {
    "id": "a1b2…",
    "created_utc": "2026-09-29T09:15:00Z",
    "old": {"path": "fw-1.4.2.bin", "sha256": "…", "manifest": {/* ingest manifest */}},
    "new": {"path": "fw-1.4.3.bin", "sha256": "…", "manifest": {}},
    "config": {"thresholds": {"tau": 0.80, "delta": 0.08}, "llm": "ollama/llama3.1:8b"}
  },

  "summary": {
    "functions": {"old": 1910, "new": 1912},
    "matches":  {"exact_hash": 1681, "struct_hash": 118, "embedding": 43,
                 "callgraph_anchor": 30, "manual": 0},
    "changed": 89, "added": 121, "removed": 28, "ambiguous": 22,
    "lift_gaps": {"old": 0, "new": 2},
    "security_relevance": {"high": 4, "medium": 17, "low": 68}
  },

  "changes": [
    {
      "id": "CH0042",
      "pair": {"old": "F0101", "new": "F0102"},
      "names": {"old": "FUN_4001a3c0", "new": "parse_header"},
      "match": {"method": "exact_hash", "confidence": 1.0},
      "edits": [
        {
          "op": "insert", "cluster": 1,
          "old_snippet": null,
          "new_snippet": "if (len > 0x40) { len = 0x40; }",
          "line": { "new": 42 }
        }
      ],
      "classifiers": [
        {
          "tag": "bound_change",
          "confidence": 0.9,
          "evidence": [
            {"kind": "edit", "id": 1},
            {"kind": "import_call", "name": "memcpy", "line": {"new": 47}},
            {"kind": "callgraph", "detail": "reachable from recv_header via F0088"}
          ]
        },
        {
          "tag": "auth_surface_change",
          "confidence": 0.8,
          "evidence": [{"kind": "callgraph", "detail": "socket → recv → … → this"}]
        }
      ],
      "security_relevance": {
        "score": "high",
        "components": {"dangerous_api_proximity": 3, "auth_surface": 2,
                        "edit_class": 3, "crypto": 0}
      },
      "hypotheses": [
        {"cwe": "CWE-190", "label": "bounds/integer hardening",
         "confidence": "medium", "evidence": ["CH0042.edit@1"]}
      ],
      "explain": {
        "narrative": "A size clamp was added before the copy into a fixed 64-byte header buffer. Combined with the unchanged memcpy, this reads as a bounds-check fix, not a behavior change for valid inputs.",
        "confidence": "medium",
        "claims": [{"id": 1, "evidence": ["CH0042.edit@1", "CH0042.classifiers@1"]}],
        "provenance": {"model": "llama3.1:8b", "prompt_version": "pv7",
                       "dropped_claims": 0}
      }
    }
  ],

  "added":   [{"id": "F0900", "name": "telemetry_loop", "size": 512,
               "first_strings": ["/dev/mcu0"]}],
  "removed": [{"id": "F0203", "name": "legacy_auth_check", "size": 300,
               "called_by": ["F0101"]}],
  "ambiguous": [{"old": "F0701", "new": "F0702",
                 "candidates": [{"sim": 0.81}, {"sim": 0.80}]}],
  "lift_gaps": [{"image": "new", "range": [1073741824, 1073750016],
                 "reason": "unanalyzable"}]
}
```

## Field semantics (selected, normative)

- `changes[].match.method` — enum from pipeline-spec §4; `manual` forced pairs flagged.
- `classifiers[].evidence` — every tag must carry ≥ 1 evidence row; renderers link to it.
- `hypotheses[]` — optional, produced by classifiers *and* explainer; `confidence` is one of
  `low|medium|high`; a hypothesis is **never** a verdict (PRODUCT_SPEC §3).
- `explain` — absent entirely when LLM disabled; `provenance.dropped_claims > 0` tells you
  validation rejected claims.
- `summary.ambiguous` — count of pairs rejected by the S3 margin rule; they also appear in
  `ambiguous[]` for human mapping.

## SARIF mapping (v0.2)

Each change with `security_relevance ∈ {high}` emits one SARIF `result`:
`ruleId = "fwdiff/<primary classifier tag>"`, `level = warning`, message = narrative +
evidence digest, location = new function address (with `--base`). Mapped hypotheses attach as
taxonomies (CWE). Full ruleset documented at implementation time.

## Markdown report template (normative skeleton)

```markdown
# fw-diff: fw-1.4.2 → fw-1.4.3
*Generated 2026-09-29T09:15Z · fw-diff 0.1.0 · Ghidra 11.3.2*

**Matched 1,872/1,910** · changed 89 · added 121 · removed 28 · ambiguous 22

## High-relevance changes (4)
### [CH0042] parse_header — HIGH · bound_change (CWE-190?)
narrative…  <details>evidence table</details>
## All changes (89)
| id | function | tags | relevance | LLM? |
…
## Appendix
- Ingest manifests · thresholds · prompt version · match method histogram
- "We could not see here" bands (lift gaps)
```
