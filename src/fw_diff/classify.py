"""Deterministic classifiers + security relevance rubric (pipeline-spec §5.4-5.5)."""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass

from .delta import calls_in_line
from .models import Change, Edit, Evidence, FunctionIR, Hypothesis, Relevance, Tag

# --- constant knowledge tables -------------------------------------------------

CRYPTO_MARKERS: dict[int, str] = {
    0x67452301: "MD5/SHA1 init A",
    0xEFCDAB89: "MD5/SHA1 init B",
    0x98BADCFE: "MD5/SHA1 init C",
    0x10325476: "MD5/SHA1 init D",
    0x428A2F98: "SHA-256 K[0]",
    0x6A09E667: "SHA-512 init h0",
    0xEDB88320: "CRC-32 poly (reflected)",
    0x04C11DB7: "CRC-32 poly",
    0x9E3779B9: "TEA/xxhash golden ratio",
    0x61C88647: "TEA delta complement",
    0xC2B2AE3D: "xxhash PRIME64",
}

AES_SBOX_ROW = frozenset(
    {
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
    }
)

MEM_UNSAFE = frozenset(
    [
        "memcpy",
        "strcpy",
        "sprintf",
        "strcat",
        "memmove",
        "bcopy",
        "strncpy",
        "snprintf",
        "gets",
        "scanf",
        "vsprintf",
    ]
)
DANGEROUS_T1 = frozenset(["system", "popen", "execve", "setuid", "setgid", "fork"])
INPUT_ROOTS = frozenset(
    ["recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "scanf", "accept", "connect"]
)


def crypto_markers_in(constants: list[int]) -> list[str]:
    found = [name for value, name in CRYPTO_MARKERS.items() if value in constants]
    sbox_hits = len(AES_SBOX_ROW & {c & 0xFF for c in constants})
    if sbox_hits >= 6:
        found.append("AES S-box constants")
    return sorted(set(found))


# --- auth-surface reachability --------------------------------------------------


def auth_surface_set(ir_list: list[FunctionIR]) -> set[str]:
    """Functions reachable from input-taking roots via calls_out (BFS)."""
    by_id = {fn.id: fn for fn in ir_list}
    roots = [
        fn.id
        for fn in ir_list
        if any(imp.removeprefix("IMPORT_") in INPUT_ROOTS for imp in fn.imports_called)
    ]
    seen: set[str] = set()
    queue: deque[str] = deque(roots)
    while queue:
        fid = queue.popleft()
        if fid in seen:
            continue
        seen.add(fid)
        fn = by_id.get(fid)
        if fn is None:
            continue
        for callee in fn.calls_out:
            if callee in by_id and callee not in seen:
                queue.append(callee)
    return seen


# --- classification context ------------------------------------------------------


@dataclass
class MatchContext:
    """Match-derived canonicalization: name->id maps per image plus pair maps."""

    old_name_to_id: dict[str, str]
    new_name_to_id: dict[str, str]
    new_to_old: dict[str, str]

    @classmethod
    def from_match(
        cls,
        old_map: dict[str, FunctionIR],
        new_map: dict[str, FunctionIR],
        match_result: object,
    ) -> MatchContext:
        pairs = getattr(match_result, "pairs", [])
        new_to_old = {p.new_id: p.old_id for p in pairs}
        return cls(
            old_name_to_id={fn.name: fn.id for fn in old_map.values()},
            new_name_to_id={fn.name: fn.id for fn in new_map.values()},
            new_to_old=new_to_old,
        )

    def canonical_call(self, name: str, side: str) -> str:
        """Canonical call token: matched-pair-aligned id, IMPORT_<name>, or raw name."""
        name_to_id = self.new_name_to_id if side == "new" else self.old_name_to_id
        fid = name_to_id.get(name)
        if fid is None:
            return (
                f"IMPORT_{name}"
                if name in MEM_UNSAFE or name in INPUT_ROOTS or _importish(name)
                else name
            )
        if side == "new" and fid in self.new_to_old:
            return self.new_to_old[fid]
        return fid


def _importish(name: str) -> bool:
    return name.islower() and not name.startswith(("FUN_", "DAT_", "f", "g", "p"))


# --- classification --------------------------------------------------------------


def classify_change(
    change: Change,
    ir_old: dict[str, FunctionIR],
    ir_new: dict[str, FunctionIR],
    auth_old: set[str],
    auth_new: set[str],
    ctx: MatchContext | None = None,
) -> None:
    """Attach classifier tags, relevance, and hypotheses to a change (mutates it)."""
    old_fn = ir_old.get(change.old_id)
    new_fn = ir_new.get(change.new_id)
    if old_fn is None or new_fn is None:
        return
    if ctx is None:
        ctx = MatchContext({}, {}, {})

    tags: list[Tag] = []
    crypto_old = crypto_markers_in(old_fn.constants)
    crypto_new = crypto_markers_in(new_fn.constants)
    crypto_changed = crypto_old != crypto_new or _crypto_constants_swapped(change, old_fn, new_fn)

    dangerous = set()
    for imp in new_fn.imports_called:
        name = imp.removeprefix("IMPORT_")
        if name in MEM_UNSAFE or name in DANGEROUS_T1:
            dangerous.add(name)

    bound_edit_idx: int | None = None
    for idx, edit in enumerate(change.edits, start=1):
        new_line = edit.new_snippet or ""
        old_line = edit.old_snippet or ""
        is_comparison = _comparison_with_constant(new_line) or _comparison_with_constant(old_line)
        if edit.op in ("insert", "update") and is_comparison and dangerous & MEM_UNSAFE:
            bound_edit_idx = idx

    if bound_edit_idx is not None:
        ev = [Evidence("edit", f"edit@{bound_edit_idx}")]
        if dangerous & MEM_UNSAFE:
            ev.append(Evidence("import_call", f"calls {', '.join(sorted(dangerous & MEM_UNSAFE))}"))
        if new_fn.id in auth_new:
            ev.append(Evidence("callgraph", "reachable from input path"))
        tags.append(Tag("bound_change", 0.9, ev))

    if crypto_changed:
        ev = [
            Evidence(
                "constant",
                f"old: {', '.join(crypto_old) or 'none'}; new: {', '.join(crypto_new) or 'none'}",
            )
        ]
        tags.append(Tag("crypto_constant_change", 0.8, ev))

    for idx, edit in enumerate(change.edits, start=1):
        if edit.op == "insert" and _IF_START.match(edit.new_snippet or ""):
            tags.append(Tag("branch_insert", 0.7, [Evidence("edit", f"edit@{idx}")]))
        if edit.op == "delete" and _IF_START.match(edit.old_snippet or ""):
            tags.append(Tag("branch_remove", 0.7, [Evidence("edit", f"edit@{idx}")]))
        if edit.op == "update" and _struct_equal_update(edit) and _constant_changed(edit):
            tags.append(
                Tag(
                    "constant_change",
                    0.85,
                    [
                        Evidence("edit", f"edit@{idx}"),
                        Evidence("constant", f"{edit.old_snippet} -> {edit.new_snippet}"),
                    ],
                )
            )
        if edit.op == "update":
            old_calls = calls_in_line(edit.old_snippet or "")
            new_calls = calls_in_line(edit.new_snippet or "")
            if old_calls and new_calls and old_calls != new_calls:
                tags.append(
                    Tag(
                        "call_target_change",
                        0.75,
                        [
                            Evidence("edit", f"edit@{idx}"),
                            Evidence("callgraph", f"{sorted(old_calls)} -> {sorted(new_calls)}"),
                        ],
                    )
                )

    if set(old_fn.strings) != set(new_fn.strings):
        tags.append(
            Tag("string_change", 0.9, [Evidence("string", "string literals differ between builds")])
        )

    if old_fn.params != new_fn.params:
        tags.append(
            Tag(
                "signature_change",
                0.95,
                [Evidence("constant", f"params {old_fn.params} -> {new_fn.params}")],
            )
        )

    if new_fn.id in auth_new or old_fn.id in auth_old:
        side = "new" if new_fn.id in auth_new else "old"
        tags.append(
            Tag(
                "auth_surface_change",
                0.8,
                [Evidence("callgraph", f"function reachable from input path in {side} image")],
            )
        )

    relevance, hypotheses = _relevance_and_hypotheses(
        change, tags, dangerous, new_fn, old_fn, auth_old, auth_new, crypto_changed
    )
    change.tags = _dedupe_tags(tags)
    change.relevance = relevance
    change.hypotheses = hypotheses


_IF_START = re.compile(r"^\s*(if|else|switch|case)\b")
_COMPARISON_RE = re.compile(r"(if|while)\b.*[<>=!]")


def _comparison_with_constant(line: str) -> bool:
    return bool(_COMPARISON_RE.search(line)) and any(c.isdigit() for c in line)


def _struct_equal_update(edit: Edit) -> bool:
    """update whose sides are equal after constant bucketing -> candidate constant change."""
    from .normalize import _NUMBER_TOKEN_RE, _TOKEN_RE, _constant_bucket, _parse_number

    def bucket(text: str) -> list[str]:
        out: list[str] = []
        for tok in _TOKEN_RE.findall(text):
            if tok.startswith('"'):
                out.append(f"S{len(tok) - 2}")
            elif _NUMBER_TOKEN_RE.match(tok):
                out.append(_constant_bucket(_parse_number(tok)))
            else:
                out.append(tok)
        return out

    a = bucket(edit.old_snippet or "")
    b = bucket(edit.new_snippet or "")
    return a == b and a != []


def _constant_changed(edit: Edit) -> bool:
    """True when numeric constants differ (string tokens excluded — those are
    string_change, not constant_change)."""
    from .normalize import _NUMBER_TOKEN_RE, _TOKEN_RE

    def nums(text: str) -> set[str]:
        return {t for t in _TOKEN_RE.findall(text) if _NUMBER_TOKEN_RE.match(t)}

    return nums(edit.old_snippet or "") != nums(edit.new_snippet or "")


def _crypto_constants_swapped(change: Change, old_fn: FunctionIR, new_fn: FunctionIR) -> bool:
    for edit in change.edits:
        if edit.op == "update":
            for c in _edit_constants(edit.old_snippet or ""):
                if c in CRYPTO_MARKERS and c not in new_fn.constants:
                    return True
            for c in _edit_constants(edit.new_snippet or ""):
                if c in CRYPTO_MARKERS and c not in old_fn.constants:
                    return True
    return False


def _edit_constants(text: str) -> list[int]:
    out = []
    for tok in re.findall(r"0[xX][0-9a-fA-F]+|\d+", text):
        try:
            out.append(int(tok, 0))
        except ValueError:  # pragma: no cover
            continue
    return out


def _relevance_and_hypotheses(
    change: Change,
    tags: list[Tag],
    dangerous: set[str],
    new_fn: FunctionIR,
    old_fn: FunctionIR,
    auth_old: set[str],
    auth_new: set[str],
    crypto_changed: bool,
) -> tuple[Relevance, list[Hypothesis]]:
    tag_names = {t.tag for t in tags}
    components: dict[str, int] = {}

    # dangerous API proximity (0-3)
    proximity = 0
    if dangerous & DANGEROUS_T1:
        proximity = 3
    elif dangerous & MEM_UNSAFE:
        proximity = 3 if ("bound_change" in tag_names or "branch_insert" in tag_names) else 2
    if "IMPORT_IMPORT_rand" in new_fn.imports_called or "rand" in dangerous:
        proximity = max(proximity, 1)
    components["dangerous_api_proximity"] = proximity

    # auth surface (0/2)
    components["auth_surface"] = 2 if (new_fn.id in auth_new or old_fn.id in auth_old) else 0

    # edit class (0-3)
    edit_class = 0
    if "bound_change" in tag_names or "branch_insert" in tag_names:
        edit_class = 3
    elif "call_target_change" in tag_names or "constant_change" in tag_names:
        edit_class = 1
    components["edit_class"] = edit_class

    # crypto (0/2)
    components["crypto"] = 2 if "crypto_constant_change" in tag_names else 0

    total = sum(components.values())
    score = "high" if total >= 5 else ("medium" if total >= 3 else "low")

    hypotheses: list[Hypothesis] = []
    if "bound_change" in tag_names:
        hypotheses.append(
            Hypothesis(
                "CWE-190",
                "bounds/integer hardening (or regression)",
                "medium",
                [f"{change.id}.classifiers@0"],
            )
        )
    if "crypto_constant_change" in tag_names:
        hypotheses.append(
            Hypothesis(
                "CWE-327",
                "crypto constant replaced — algorithm/key material change",
                "low",
                [f"{change.id}.classifiers@1"],
            )
        )
    if components["auth_surface"] == 2:
        hypotheses.append(
            Hypothesis(
                None,
                "attack-surface change in an input-handling function",
                "low",
                [
                    f"{change.id}.classifiers@{len([t for t in tags if t.tag == 'auth_surface_change']) or 1}"
                ],
            )
        )

    return Relevance(score, components), hypotheses


def _dedupe_tags(tags: list[Tag]) -> list[Tag]:
    seen: dict[str, Tag] = {}
    for tag in tags:
        if tag.tag not in seen:
            seen[tag.tag] = tag
    return [seen[k] for k in sorted(seen)]


def classify_removed(fn: FunctionIR, auth_old: set[str]) -> dict[str, object]:
    """Facts entry for a removed function."""
    crypto = crypto_markers_in(fn.constants)
    return {
        "id": fn.id,
        "name": fn.name,
        "size": fn.size,
        "called_by": fn.calls_in,
        "auth_surface": fn.id in auth_old,
        "crypto_markers": crypto,
    }


def classify_added(fn: FunctionIR, auth_new: set[str]) -> dict[str, object]:
    return {
        "id": fn.id,
        "name": fn.name,
        "size": fn.size,
        "first_strings": fn.strings[:3],
        "auth_surface": fn.id in auth_new,
        "crypto_markers": crypto_markers_in(fn.constants),
        "imports_called": fn.imports_called,
    }
