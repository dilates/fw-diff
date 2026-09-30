# Release Process

| | |
|---|---|
| **Owner** | Release manager (rotating) |
| **Cadence** | minor: ~every 6–8 weeks · patch: as needed · majors: rare, planned |

## 1. Versioning

SemVer. Pre-1.0: `0.x` minor releases may break CLI/flags (documented in CHANGELOG under
**Changed/Breaking**); `facts.json` schema has its **own** version and policy
(report-format §Compatibility) independent of tool SemVer.

## 2. Release train

1. **Freeze**: `release/x.y` branch cut; only fixes land.
2. **Release gate** (automated, see testing-strategy §9): full CI green incl. corpus matrix,
   reproducibility job, eval scores ≥ PRODUCT_SPEC §5 targets, perf budget met.
3. **CHANGELOG**: drafted from conventional commits; breaking changes called out at top.
4. **Artifacts**: PyPI sdist+wheel (trusted publishing), GHCR images (`fw-diff`,
   `fw-diff-worker:ghidra-<ver>`) with provenance attestations, docs site build (versioned).
5. **Signing**: artifacts signed; SBOM (CycloneDX) attached (v1.0 gate, earlier best-effort).
6. **Announce**: GitHub Release with notes; highlights ≤ 10 bullets; corpus/eval score table
   for releases that touched matching or explainer.

## 3. Hotfixes

Branch from the release tag, cherry-pick fixes, re-run release gate subset (full CI + affected
layer), patch bump, re-sign. Reproducibility-affecting fixes always ship as minor bumps for
pre-1.0 (facts may differ from prior patch releases).

## 4. Post-release

- Update roadmap checkboxes and milestone statuses
- Threat-model review if worker sandboxing or LLM contract changed (THREAT_MODEL §5)
- Doc site deployment verified offline (no external URLs rule — ADR-0010)

## 5. Support windows

Pre-1.0: latest minor only, patches as needed. Post-1.0: latest minor + previous minor for
90 days.