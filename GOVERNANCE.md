# Governance

| | |
|---|---|
| **Status** | Active |

## Roles

- **Contributors** — anyone whose PR lands. Listed in commit history.
- **Component owners** — named in CODEOWNERS; gate-keep their component per CONTRIBUTING
  review rules.
- **Maintainers** — merge rights, release management, roadmap stewardship. Currently the
  founding team; additions by consensus of existing maintainers after sustained contribution
  (≥ 3 months, ≥ 10 substantive PRs or equivalent docs/spec work).

## Decision-making

1. **Trivial** (typos, docs, test cases): PR review suffices.
2. **Normal** (features within an approved spec): owner approval + CI green.
3. **Architectural**: an ADR is required. Propose in an `RFC` issue → discussion → maintainer
   consensus → ADR recorded (Accepted/Rejected with rationale). The ADR is the decision; the
   issue is just the debate.
4. **Disagreements**: maintainer supermajority decides; dissent is recorded in the ADR, not
   deleted. Reversal = superseding ADR, never silent edits.

## What's frozen

- `facts.json` schema major versions (compatibility policy in report-format)
- Plugin API v1 (12-month stability from v0.3)
- Project posture: facts-before-narrative, local-first, hypotheses-not-verdicts (ADR-0003,
  ADR-0004). Changing these requires a major release and explicit maintainer consensus.

## Community corpus

Source+build-recipe contributions only (ADR-0009 rules): no binaries, no blobs, no
vendor samples. Corpus reviewers = matching owner + one maintainer.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md); maintainers enforce it uniformly.