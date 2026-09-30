"""Delta engine: edit extraction + clustering (pipeline-spec §5).

v0.1 implements statement-level diff on normalized exact text: Ghidra emits roughly one
statement per line, so lines are the diff unit; GumTree-style AST diff supersedes this in
v0.2 (ROADMAP). Clusters of adjacent edit ops are the unit classifiers and reports work on.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from .models import Edit, FunctionIR
from .normalize import NormalizedFunction

IF_START_RE = re.compile(r"^\s*(if|else|switch|case)\b")
_FG_TOKEN_RE = re.compile(r"^[fg]\d+$")


def _neutralize(line: str) -> list[str]:
    """Token view with ONLY cross-image identifiers neutralized (f/g -> FCALL/GDATA);
    constants and strings are signal and stay exact."""
    from .normalize import _TOKEN_RE

    return [
        "FCALL"
        if tok.startswith("f") and _FG_TOKEN_RE.match(tok)
        else ("GDATA" if tok.startswith("g") and _FG_TOKEN_RE.match(tok) else tok)
        for tok in _TOKEN_RE.findall(line)
    ]


CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


@dataclass
class PairDelta:
    old_lines: list[str]
    new_lines: list[str]
    edits: list[Edit]


def _statements(text: str) -> list[str]:
    return [ln for ln in (ln.strip() for ln in text.splitlines()) if ln]


def diff_pair(old_norm: NormalizedFunction, new_norm: NormalizedFunction) -> PairDelta:
    """Line-level diff of two normalized texts, clustered into edits."""
    old_lines = _statements(old_norm.text_exact)
    new_lines = _statements(new_norm.text_exact)
    edits: list[Edit] = []
    cluster = 0
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    pending: list[tuple[str, int, int, int, int]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            if pending:
                cluster += 1
                _emit_cluster(pending, old_lines, new_lines, cluster, edits)
                pending = []
            continue
        pending.append((tag, i1, i2, j1, j2))
    if pending:
        cluster += 1
        _emit_cluster(pending, old_lines, new_lines, cluster, edits)
    return PairDelta(old_lines, new_lines, edits)


def _emit_cluster(
    pending: list[tuple[str, int, int, int, int]],
    old_lines: list[str],
    new_lines: list[str],
    cluster: int,
    edits: list[Edit],
) -> None:
    for tag, i1, i2, j1, j2 in pending:
        if tag == "delete":
            for i in range(i1, i2):
                edits.append(Edit("delete", old_lines[i], None, i + 1, None, cluster))
        elif tag == "insert":
            for j in range(j1, j2):
                edits.append(Edit("insert", None, new_lines[j], None, j + 1, cluster))
        elif tag == "replace":
            for i in range(i1, i2):
                for j in range(j1, j2):
                    edits.append(Edit("update", old_lines[i], new_lines[j], i + 1, j + 1, cluster))
                    break
            # extra old/new lines in a replace get delete/insert semantics
            if i2 - i1 > j2 - j1:
                for i in range(i1 + (j2 - j1), i2):
                    edits.append(Edit("delete", old_lines[i], None, i + 1, None, cluster))
            elif j2 - j1 > i2 - i1:
                for j in range(j1 + (i2 - i1), j2):
                    edits.append(Edit("insert", None, new_lines[j], None, j + 1, cluster))


def trim_window(lines: list[str], hot: set[int], radius: int = 10, cap: int = 60) -> list[str]:
    """Trim a pseudocode window to the hot lines (explain input contract)."""
    if not hot or not lines:
        return lines[:cap]
    lo = max(1, min(hot) - radius)
    hi = min(len(lines), max(hot) + radius)
    window = lines[lo - 1 : hi]
    return window[:cap]


def filter_layout_noise(edits: list[Edit]) -> list[Edit]:
    """Drop update edits that differ only in f<ord>/g<ord> identifiers (layout artifacts,
    not code changes); a pair whose edits all vanish is not a change."""
    kept: list[Edit] = []
    for edit in edits:
        if (
            edit.op == "update"
            and edit.old_snippet
            and edit.new_snippet
            and _neutralize(edit.old_snippet) == _neutralize(edit.new_snippet)
        ):
            continue
        kept.append(edit)
    return kept


def changed_line_numbers(delta: PairDelta) -> set[int]:
    hot: set[int] = set()
    for edit in delta.edits:
        if edit.line_new is not None:
            hot.add(edit.line_new)
    return hot


def calls_in_line(line: str) -> set[str]:
    return {m.group(1) for m in CALL_NAME_RE.finditer(line)}


def strings_in_text(text: str) -> list[str]:
    return STRING_RE.findall(text)


def function_by_id(ir_map: dict[str, FunctionIR], fid: str) -> FunctionIR | None:
    return ir_map.get(fid)
