# Getting Started — walkthrough

This guide walks a full session on a pair of router firmware images, showing real command
shapes and what to look for in the outputs. For a zero-setup taste first: `fw-diff demo
--out out/` runs the entire pipeline on bundled fixture IR.

## 1. Environment check

```bash
export GHIDRA_INSTALL_DIR=~/re/ghidra_11.3.2_PUBLIC   # or /opt/ghidra
fw-diff doctor
# ✔ ghidra 11.3.2 found · pyghidra present · java 21 · 128 GB free · ollama reachable
# ✗ pyghidra fail  ->  pip install 'fw-diff[ghidra]'
```

`doctor` is your first stop whenever something feels wrong (runbook §4).

## 2. Run a session

```bash
fw-diff explain fw-1.4.2.bin fw-1.4.3.bin \
    --base 0x40000000 --arch armv7 \
    --out out/
```

What happens, in order (pipeline-spec §1–6):

1. **ingest** — detects a raw ARM image (no ELF header), writes the manifest, prints its
   decision (`detected: raw flat binary, armv7, base 0x40000000 — pass --arch/--base to
   override`) so you can audit it.
2. **lift** — two Ghidra passes; first run is analysis-bound (minutes), second identical run
   hits the cache. `LiftGap` bands are shown if regions were unanalyzable.
3. **match** — stage histogram prints as it goes. Watch the `ambiguous` count: those pairs
   were *deliberately not guessed* (pipeline-spec §4 S3 margin rule).
4. **delta + classify** — deterministic; the security relevance scores carry component
   breakdowns you can drill into in the HTML report.
5. **explain** — the LLM annotates facts; every claim links to evidence; dropped-claim counts
   are recorded. This stage is skippable (`--llm off`) with identical facts.

## 3. Read the outputs

- **`out/facts.json`** — start at `summary`; the `changes[]` array is what CI would gate on.
  Check `provenance.dropped_claims` > 0? Then some model claims were rejected by validation —
  read the report to see which survived.
- **`out/report.html`** — ranked by security relevance. For the top entries: click the
  evidence rows to see the exact edits (e.g., inserted `cmp #0x40` before `memcpy`), the
  callgraph path that makes it "auth-surface", and the side-by-side pseudocode. LLM narrative
  is visually marked as model output — treat it as a hint, verify via evidence.
- **`out/report.md`** — paste into vendor communication or your notes.

## 4. Gate it in CI

```yaml
# policy.yaml
fail_on:
  - classifier: bound_change
    where: security_relevance == high
  - classifier: crypto_constant_change
  - removed_function:
      reachable_from_input: true
warn_on:
  - classifier: string_change
```

```bash
fw-diff ci fw-1.4.2.bin fw-1.4.3.bin --policy policy.yaml --worker-mode docker
echo $?
# 1  (with machine-readable reason printed as JSON)
```

`ci` mode never uses the LLM for decisions — policies read only deterministic facts
(THREAT_MODEL §3.2).

## 5. Fix what the tool couldn't match

```bash
fw-diff explain fw-1.4.2.bin fw-1.4.3.bin --map mymap.tsv   # TSV: old_id, new_id, reason
```

Manual mappings are labeled `match_method=manual` (confidence 1.0) and appear distinct in
reports; ambiguous pairs are listed in `facts.json` so you know what to map.

## 6. Where to go next

- Zero-setup first run: `fw-diff demo --out out/` (bundled fixture IR, no Ghidra)
- Normalization/matching internals: [design/pipeline-spec.md](../design/pipeline-spec.md)
- Extending with a custom classifier: [design/plugin-api.md](../design/plugin-api.md)
- Anatomy of every field: [design/report-format.md](../design/report-format.md)
- Hardening for hostile images: [THREAT_MODEL.md](../THREAT_MODEL.md) + runbook §3