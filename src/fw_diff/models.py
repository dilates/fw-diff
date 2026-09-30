"""Core data model: FunctionIR, manifests, match results, changes, and the facts document.

All classes are deterministic by construction: ``to_dict`` emits only stable fields and
``from_dict`` restores them. ``FactsDoc.to_json`` produces byte-identical output for identical
inputs (ARCHITECTURE principle 3).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

MATCH_METHODS = ("exact_hash", "struct_hash", "callgraph_anchor", "embedding", "manual")


@dataclass
class FunctionIR:
    """One lifted function (ARCHITECTURE §3.1)."""

    id: str
    image: str  # "old" | "new"
    name: str  # raw Ghidra name, e.g. FUN_4001a4f0
    symbols: list[str] = field(default_factory=list)  # recovered aliases (non-Ghidra names)
    arch: str = "unknown"
    addr: int = 0
    size: int = 0
    params: int = 0
    entry: bool = False
    pseudocode_raw: str = ""
    pseudocode_norm: str = ""  # filled by normalize
    h_exact: str = ""  # normalized hash, constants preserved
    h_struct: str = ""  # normalized hash, constants wildcarded
    calls_out: list[str] = field(default_factory=list)  # function ids or IMPORT_<name>
    calls_in: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    constants: list[int] = field(default_factory=list)
    imports_called: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "image": self.image,
            "name": self.name,
            "symbols": self.symbols,
            "arch": self.arch,
            "addr": self.addr,
            "size": self.size,
            "params": self.params,
            "entry": self.entry,
            "pseudocode_raw": self.pseudocode_raw,
            "pseudocode_norm": self.pseudocode_norm,
            "h_exact": self.h_exact,
            "h_struct": self.h_struct,
            "calls_out": self.calls_out,
            "calls_in": self.calls_in,
            "strings": self.strings,
            "constants": self.constants,
            "imports_called": self.imports_called,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FunctionIR:
        return cls(
            id=data["id"],
            image=data["image"],
            name=data["name"],
            symbols=list(data.get("symbols", [])),
            arch=data.get("arch", "unknown"),
            addr=int(data.get("addr", 0)),
            size=int(data.get("size", 0)),
            params=int(data.get("params", 0)),
            entry=bool(data.get("entry", False)),
            pseudocode_raw=data.get("pseudocode_raw", ""),
            pseudocode_norm=data.get("pseudocode_norm", ""),
            h_exact=data.get("h_exact", ""),
            h_struct=data.get("h_struct", ""),
            calls_out=list(data.get("calls_out", [])),
            calls_in=list(data.get("calls_in", [])),
            strings=list(data.get("strings", [])),
            constants=[int(c) for c in data.get("constants", [])],
            imports_called=list(data.get("imports_called", [])),
            meta=dict(data.get("meta", {})),
        )


@dataclass
class LiftTarget:
    """A concrete binary to lift out of an ingested image."""

    path: str
    arch: str
    base: int | None


@dataclass
class ImageManifest:
    """Audit trail of ingest decisions for one input image."""

    path: str
    sha256: str
    formats: list[str] = field(default_factory=list)  # detected format chain
    targets: list[LiftTarget] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "formats": self.formats,
            "targets": [{"path": t.path, "arch": t.arch, "base": t.base} for t in self.targets],
            "notes": self.notes,
        }


@dataclass
class Evidence:
    """Pointer to concrete data backing a claim/tag (report-format)."""

    kind: str  # edit | import_call | callgraph | string | constant
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "detail": self.detail}


@dataclass
class Tag:
    """A classifier tag with evidence (report-format)."""

    tag: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tag": self.tag,
            "confidence": self.confidence,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class Edit:
    """One clustered edit op (delta engine)."""

    op: str  # insert | delete | replace | move
    old_snippet: str | None
    new_snippet: str | None
    line_old: int | None
    line_new: int | None
    cluster: int

    def to_dict(self) -> dict[str, Any]:
        line: dict[str, int] = {}
        if self.line_new is not None:
            line["new"] = self.line_new
        if self.line_old is not None:
            line["old"] = self.line_old
        return {
            "op": self.op,
            "cluster": self.cluster,
            "old_snippet": self.old_snippet,
            "new_snippet": self.new_snippet,
            "line": line,
        }


@dataclass
class Hypothesis:
    """Possible interpretation — never a verdict (PRODUCT_SPEC §3)."""

    cwe: str | None
    label: str
    confidence: str  # low | medium | high
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "label": self.label,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class Relevance:
    """Security relevance rubric output with component breakdown (pipeline-spec §5.5)."""

    score: str  # high | medium | low
    components: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "components": self.components}


@dataclass
class ExplainBlock:
    """LLM annotation; absent when --llm off (report-format)."""

    narrative: str
    confidence: str
    claims: list[dict[str, Any]]
    provenance: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "narrative": self.narrative,
            "confidence": self.confidence,
            "claims": self.claims,
            "provenance": self.provenance,
        }


@dataclass
class Change:
    """One changed function pair — the unit reports and policies work on."""

    id: str
    old_id: str
    new_id: str
    old_name: str
    new_name: str
    match_method: str
    match_confidence: float
    edits: list[Edit] = field(default_factory=list)
    tags: list[Tag] = field(default_factory=list)
    relevance: Relevance = field(default_factory=lambda: Relevance("low", {}))
    hypotheses: list[Hypothesis] = field(default_factory=list)
    explain: ExplainBlock | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "pair": {"old": self.old_id, "new": self.new_id},
            "names": {"old": self.old_name, "new": self.new_name},
            "match": {"method": self.match_method, "confidence": self.match_confidence},
            "edits": [e.to_dict() for e in self.edits],
            "classifiers": [t.to_dict() for t in self.tags],
            "security_relevance": self.relevance.to_dict(),
            "hypotheses": [h.to_dict() for h in self.hypotheses],
        }
        if self.explain is not None:
            out["explain"] = self.explain.to_dict()
        return out


@dataclass
class SessionInfo:
    """Session block of facts.json; deterministic mode derives id/timestamp from inputs."""

    id: str
    created_utc: str | None
    old_manifest: ImageManifest
    new_manifest: ImageManifest
    config: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_utc": self.created_utc,
            "old": self.old_manifest.to_dict(),
            "new": self.new_manifest.to_dict(),
            "config": self.config,
        }


@dataclass
class FactsDoc:
    """The deterministic deliverable (docs/design/report-format.md schema v1)."""

    schema_version: int
    tool_name: str
    tool_version: str
    ghidra: str | None
    session: SessionInfo
    summary: dict[str, Any]
    changes: list[Change]
    added: list[dict[str, Any]]
    removed: list[dict[str, Any]]
    ambiguous: list[dict[str, Any]]
    lift_gaps: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": {"name": self.tool_name, "version": self.tool_version, "ghidra": self.ghidra},
            "session": self.session.to_dict(),
            "summary": self.summary,
            "changes": [c.to_dict() for c in self.changes],
            "added": self.added,
            "removed": self.removed,
            "ambiguous": self.ambiguous,
            "lift_gaps": self.lift_gaps,
        }

    def to_json(self) -> str:
        """Byte-reproducible serialization."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2) + "\n"
