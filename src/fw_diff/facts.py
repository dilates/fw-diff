"""Facts builder: assembles the schema-v1 FactsDoc from match + delta + classify output."""

from __future__ import annotations

import contextlib
import hashlib
from dataclasses import dataclass

from . import __version__
from .classify import auth_surface_set, classify_added, classify_removed
from .delta import diff_pair, filter_layout_noise
from .match import MatchResult
from .models import Change, FactsDoc, FunctionIR, SessionInfo
from .normalize import NormalizedFunction

SCHEMA_VERSION = 1


def assign_ids(ir_list: list[FunctionIR], offset: int = 0) -> list[FunctionIR]:
    """Deterministic F%04d ids ordered by (address, name); mutates and returns the list.

    ``offset`` continues the numbering across images so ids are session-unique:
    old side F0001..Fn, new side F(n+1).. (report-format session id convention).
    """
    ordered = sorted(ir_list, key=lambda f: (f.addr, f.name))
    for idx, fn in enumerate(ordered, start=offset + 1):
        fn.id = f"F{idx:04d}"
    return ordered


@dataclass
class DeltaOutput:
    changes: list[Change]
    auth_old: set[str]
    auth_new: set[str]


def compute_changes(
    old_ir: list[FunctionIR],
    new_ir: list[FunctionIR],
    match_result: MatchResult,
    old_norm: dict[str, NormalizedFunction],
    new_norm: dict[str, NormalizedFunction],
) -> DeltaOutput:
    """Build Change objects for every matched pair whose code or signature differs."""
    old_map = {fn.id: fn for fn in old_ir}
    new_map = {fn.id: fn for fn in new_ir}
    auth_old = auth_surface_set(old_ir)
    auth_new = auth_surface_set(new_ir)

    changes: list[Change] = []
    for pair in sorted(match_result.pairs, key=lambda p: (new_map[p.new_id].addr, p.new_id)):
        old_fn, new_fn = old_map[pair.old_id], new_map[pair.new_id]
        if old_fn.h_exact == new_fn.h_exact and old_fn.params == new_fn.params:
            continue  # identical — not a change
        delta = diff_pair(old_norm[old_fn.id], new_norm[new_fn.id])
        edits = filter_layout_noise(delta.edits)
        if not edits and old_fn.params == new_fn.params:
            continue  # identical modulo layout ordinals — not a change
        change = Change(
            id="",  # assigned after sorting
            old_id=old_fn.id,
            new_id=new_fn.id,
            old_name=old_fn.name,
            new_name=new_fn.name,
            match_method=pair.method,
            match_confidence=pair.confidence,
            edits=edits,
        )
        _tag_pair(change, old_fn, new_fn, old_map, new_map, auth_old, auth_new, match_result)
        changes.append(change)

    changes.sort(key=lambda c: (new_map[c.new_id].addr, c.new_id))
    for idx, change in enumerate(changes, start=1):
        change.id = f"CH{idx:04d}"
    return DeltaOutput(changes=changes, auth_old=auth_old, auth_new=auth_new)


def _tag_pair(
    change: Change,
    old_fn: FunctionIR,
    new_fn: FunctionIR,
    old_map: dict[str, FunctionIR],
    new_map: dict[str, FunctionIR],
    auth_old: set[str],
    auth_new: set[str],
    match_result: MatchResult,
) -> None:
    # imported here to avoid a circular import at module load
    from .classify import MatchContext, classify_change
    from .plugins import apply_plugin_classifiers, load_classifiers

    ctx = MatchContext.from_match(old_map, new_map, match_result)
    classify_change(change, old_map, new_map, auth_old, auth_new, ctx)
    # plugin surface must never break the deterministic core
    with contextlib.suppress(Exception):
        apply_plugin_classifiers(change, old_fn, new_fn, load_classifiers())


def build_facts(
    session: SessionInfo,
    old_ir: list[FunctionIR],
    new_ir: list[FunctionIR],
    match_result: MatchResult,
    changes: list[Change],
    auth_old: set[str],
    auth_new: set[str],
    *,
    ghidra_version: str | None = None,
) -> FactsDoc:
    old_map = {fn.id: fn for fn in old_ir}
    new_map = {fn.id: fn for fn in new_ir}

    counts = match_result.method_counts()
    rel_hist: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for change in changes:
        rel_hist[change.relevance.score] += 1

    summary = {
        "functions": {"old": len(old_ir), "new": len(new_ir)},
        "matches": counts,
        "changed": len(changes),
        "added": len(match_result.added),
        "removed": len(match_result.removed),
        "ambiguous": len(match_result.ambiguous),
        "lift_gaps": {"old": 0, "new": 0},
        "security_relevance": rel_hist,
        "skipped_stages": match_result.skipped_stages,
    }

    added = [classify_added(new_map[fid], auth_new) for fid in sorted(match_result.added)]
    removed = [classify_removed(old_map[fid], auth_old) for fid in sorted(match_result.removed)]
    ambiguous = sorted(
        match_result.ambiguous,
        key=lambda e: (str(e.get("new", "")), str(e.get("old", ""))),
    )

    return FactsDoc(
        schema_version=SCHEMA_VERSION,
        tool_name="fw-diff",
        tool_version=__version__,
        ghidra=ghidra_version,
        session=session,
        summary=summary,
        changes=changes,
        added=added,
        removed=removed,
        ambiguous=ambiguous,
        lift_gaps=[],
    )


def deterministic_session_id(old_sha: str, new_sha: str) -> str:
    return hashlib.sha256(f"{old_sha}|{new_sha}|{__version__}".encode()).hexdigest()[:16]
