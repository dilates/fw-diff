"""SARIF 2.1 renderer (ROADMAP v0.2): high/medium relevance changes -> code scanning.

Each `security_relevance == high` change becomes a `warning` result; medium becomes `note`.
Rules are emitted per classifier tag observed. Deterministic output; consumed by
`fw-diff ci` consumers and GitHub code scanning.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .models import FactsDoc

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _rules(doc: FactsDoc) -> list[dict[str, Any]]:
    tags: dict[str, str] = {}
    for change in doc.changes:
        for tag in change.tags:
            tags.setdefault(tag.tag, tag.tag.replace("_", " "))
    return [
        {
            "id": f"fwdiff/{tag}",
            "shortDescription": {"text": f"fw-diff classifier: {desc}"},
            "helpUri": "https://github.com/dilates/fw-diff/blob/main/docs/design/pipeline-spec.md",
        }
        for tag, desc in sorted(tags.items())
    ]


def render_sarif(doc: FactsDoc) -> dict[str, Any]:
    new_uri = doc.session.new_manifest.path
    results: list[dict[str, Any]] = []
    for change in sorted(doc.changes, key=lambda c: c.id):
        if change.relevance.score == "low":
            continue
        level = "warning" if change.relevance.score == "high" else "note"
        primary = change.tags[0].tag if change.tags else "uncategorized"
        evidence = "; ".join(
            f"{t.tag}: {ev.kind}:{ev.detail}" for t in change.tags for ev in t.evidence
        )
        message = change.explain.narrative if change.explain else primary
        if evidence:
            message = f"{message} [evidence: {evidence}]"
        hypotheses = "; ".join(
            f"{h.cwe or 'CWE-?'} {h.label} ({h.confidence})" for h in change.hypotheses
        )
        if hypotheses:
            message = f"{message} [hypotheses: {hypotheses}]"
        results.append(
            {
                "ruleId": f"fwdiff/{primary}",
                "level": level,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": new_uri},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [{"fullyQualifiedName": change.new_name}],
                    }
                ],
                "partialFingerprints": {"fwDiffChangeId": change.id},
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fw-diff",
                        "version": __version__,
                        "informationUri": "https://github.com/dilates/fw-diff",
                        "rules": _rules(doc),
                    }
                },
                "results": results,
            }
        ],
    }
