"""Normalization of decompiled pseudocode (pipeline-spec §3 — normative).

Ghidra-invented identifiers are functions of addresses and allocation order, so raw
decompiled text is not comparable across builds (ADR-0007). This module implements:

* identifier canonicalization — ``FUN_hex`` -> ``f<ord>`` per image (ordered by address),
  ``DAT_/PTR_/s_/CONCAT`` -> ``g<ord>`` per image, Ghidra locals -> ``l<ord>`` by first
  appearance within the function, ``param_N`` -> ``p<N>``
* two hash levels — ``h_exact`` (constants preserved) and ``h_struct`` (numeric constants
  bucketed by width C1/C2/C4/C8, string literals -> ``S<len>``)
* extraction of call targets, string literals, and numeric constants from the *exact* text
  (classifiers need un-bucketed values)

Everything here is a pure function of its inputs: same text in, same hashes out.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field

from .models import FunctionIR

# ---------------------------------------------------------------------------
# Token classification
# ---------------------------------------------------------------------------

KEYWORDS = frozenset(
    [
        "if",
        "else",
        "for",
        "while",
        "return",
        "switch",
        "case",
        "default",
        "break",
        "continue",
        "do",
        "goto",
        "sizeof",
        "int",
        "void",
        "char",
        "short",
        "long",
        "unsigned",
        "signed",
        "float",
        "double",
        "struct",
        "union",
        "enum",
        "typedef",
        "const",
        "static",
        "extern",
        "volatile",
        "inline",
        "register",
        "bool",
    ]
)

# Ghidra type tokens carry size suffixes: undefined4, uint, ulonglong, ushort, ...
_TYPE_RE = re.compile(
    r"^(u?int|undefined|ushort|ulonglong|ulong|uint64|uint32|uint16|uint8|"
    r"byte|word|dword|qword|code|bool|float|double|wchar)([1-8])?$"
)

_FUN_RE = re.compile(r"^FUN_([0-9a-fA-F]+)$")
_GLOBAL_RE = re.compile(r"^(?:_DAT_|DAT_|PTR_|s_)([0-9a-fA-F]+)")
_CONCAT_RE = re.compile(r"^CONCAT[0-9a-fA-F]+$")
_PARAM_RE = re.compile(r"^param_(\d+)$")
_HEX_NUM_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
_DEC_NUM_RE = re.compile(r"^\d+$")

_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|0[xX][0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]*|\d+|\S')
_FG_RE = re.compile(r"^[fg]\d+$")
_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_NUMBER_TOKEN_RE = re.compile(r"^(0[xX][0-9a-fA-F]+|\d+)$")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# Identifiers that look like Ghidra locals but must never be canonicalized away.
_GHIDRA_LOCAL_HINT_RE = re.compile(
    r"^(u|i|p|f|d|h|c|l|au|pu|pi|pc|pd|pf|pl|ps|in_|unaff_|extraout_|local_|"
    r"auStack|uStack|in_?register|DAT)"  # DAT caught by global rule first
)


def _is_type_token(tok: str) -> bool:
    return bool(_TYPE_RE.match(tok)) or tok in KEYWORDS


def _constant_bucket(value: int) -> str:
    """Width bucket per pipeline-spec §3.2: C1 < 2^8, C2 < 2^16, C4 < 2^32, else C8."""
    if value < 0:
        value = -value
    if value < 2**8:
        return "C1"
    if value < 2**16:
        return "C2"
    if value < 2**32:
        return "C4"
    return "C8"


def _parse_number(tok: str) -> int:
    return int(tok, 0)  # handles 0x… and decimal


@dataclass
class ImageNameMaps:
    """Per-image canonical maps; deterministic (address-ordered)."""

    fun_map: dict[str, str] = field(default_factory=dict)  # FUN_4001a4f0 -> f1
    global_map: dict[str, str] = field(default_factory=dict)  # DAT_4002ab10 -> g1
    rev_fun_map: dict[str, str] = field(default_factory=dict)  # f1 -> FUN_…

    @classmethod
    def build(cls, pseudocodes: list[str]) -> ImageNameMaps:
        fun_addrs: dict[int, str] = {}
        glob_addrs: dict[int, str] = {}
        for text in pseudocodes:
            for tok in _TOKEN_RE.findall(text):
                m = _FUN_RE.match(tok)
                if m:
                    fun_addrs.setdefault(int(m.group(1), 16), tok)
                    continue
                m = _GLOBAL_RE.match(tok)
                if m:
                    glob_addrs.setdefault(int(m.group(1), 16), tok)
                    continue
                if _CONCAT_RE.match(tok):
                    # CONCATnn — order-preserving: sort by token to be deterministic
                    glob_addrs.setdefault(_concat_sort_key(tok), tok)
        maps = cls()
        for ord_, (_, name) in enumerate(sorted(fun_addrs.items()), start=1):
            maps.fun_map[name] = f"f{ord_}"
            maps.rev_fun_map[f"f{ord_}"] = name
        for ord_, (_, name) in enumerate(sorted(glob_addrs.items()), start=1):
            maps.global_map[name] = f"g{ord_}"
        return maps


def _concat_sort_key(tok: str) -> int:
    # CONCAT99_a_b: primary key is the numeric part, fallback string
    m = re.match(r"^CONCAT(\d+)", tok)
    return int(m.group(1)) if m else 0


@dataclass
class NormalizedFunction:
    """Result of normalizing one function."""

    text_exact: str
    text_struct: str
    h_exact: str
    h_struct: str
    struct_tokens: list[str]
    call_names: list[str]  # canonical call targets: f-ids, preserved names
    strings: list[str]  # exact string literals, first-appearance order
    constants: list[int]  # numeric constants, first-appearance order, deduplicated


def _collapse_ws(text: str) -> str:
    lines = []
    for line in text.splitlines():
        line = " ".join(line.split())
        if line:
            lines.append(line)
    return "\n".join(lines)


def _normalize_line_tokens(
    line: str,
    maps: ImageNameMaps,
    local_ord: dict[str, str],
    strings: list[str],
    constants_seen: dict[int, None],
) -> list[str]:
    """Normalize one source line into canonical exact tokens."""
    out: list[str] = []
    for tok in _TOKEN_RE.findall(line):
        if tok.startswith('"'):
            out.append(tok)
            strings.append(tok)
            continue
        if _HEX_NUM_RE.match(tok) or _DEC_NUM_RE.match(tok):
            out.append(tok)
            constants_seen.setdefault(_parse_number(tok), None)
            continue
        m = _FUN_RE.match(tok)
        if m:
            out.append(maps.fun_map.get(tok, tok.lower()))
            continue
        if _CONCAT_RE.match(tok) or _GLOBAL_RE.match(tok):
            out.append(maps.global_map.get(tok, tok.lower()))
            continue
        m = _PARAM_RE.match(tok)
        if m:
            out.append(f"p{m.group(1)}")
            continue
        if _is_type_token(tok):
            out.append(tok)
            continue
        if any(c.isdigit() for c in tok) and not tok.startswith("0"):
            # Ghidra local (uVar1, auStack_28, in_R0, local_c, unaff_r4, …)
            out.append(local_ord.setdefault(tok, f"l{len(local_ord) + 1}"))
            continue
        # preserved: real symbol names, imports, keywords
        out.append(tok)
    return out


def normalize_function(
    pseudocode_raw: str,
    maps: ImageNameMaps,
    *,
    image_fun_ids: dict[str, str] | None = None,
) -> NormalizedFunction:
    """Normalize ``pseudocode_raw`` and compute hashes/extractions.

    ``image_fun_ids`` optionally maps canonical ``f<ord>`` back to session function ids
    (FUN_hex -> id); used to resolve call targets to FunctionIR ids.
    """
    lines = _collapse_ws(pseudocode_raw).splitlines()
    local_ord: dict[str, str] = {}
    strings: list[str] = []
    constants_seen: dict[int, None] = {}
    exact_lines: list[list[str]] = []

    for line in lines:
        exact_lines.append(_normalize_line_tokens(line, maps, local_ord, strings, constants_seen))

    # call targets: identifier immediately followed by '(' in the exact token stream
    call_targets: list[str] = []
    prev = ""
    for tokens_line in exact_lines:
        for tok in tokens_line:
            if tok == "(" and prev and prev not in KEYWORDS and not _NUMBER_TOKEN_RE.match(prev):
                call_targets.append(prev)
            prev = tok

    text_exact = "\n".join(" ".join(line) for line in exact_lines)

    # struct text: constants bucketed, strings by length, cross-image identifiers
    # (f<ord>/g<ord>) neutralized — ordinals are image-layout artifacts and must not
    # influence cross-build comparison (ADR-0007 consequence; see pipeline-spec §3.2)
    struct_lines: list[list[str]] = []
    for tokens_line in exact_lines:
        sline: list[str] = []
        for tok in tokens_line:
            if tok.startswith('"'):
                sline.append(f"S{len(tok) - 2}")
            elif _NUMBER_TOKEN_RE.match(tok):
                sline.append(_constant_bucket(_parse_number(tok)))
            elif _FG_RE.match(tok):
                sline.append("FCALL" if tok.startswith("f") else "GDATA")
            else:
                sline.append(tok)
        struct_lines.append(sline)
    text_struct = "\n".join(" ".join(line) for line in struct_lines)
    struct_tokens: list[str] = [t for line in struct_lines for t in line]

    # resolve call targets to session ids where possible
    resolved: list[str] = []
    for target in call_targets:
        if image_fun_ids and target in image_fun_ids:
            resolved.append(image_fun_ids[target])
        elif image_fun_ids and maps.rev_fun_map.get(target) in image_fun_ids:
            resolved.append(image_fun_ids[maps.rev_fun_map[target]])
        else:
            resolved.append(f"IMPORT_{target}" if _looks_import(target) else target)

    def _digest(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    return NormalizedFunction(
        text_exact=text_exact,
        text_struct=text_struct,
        h_exact=_digest(text_exact),
        h_struct=_digest(text_struct),
        struct_tokens=struct_tokens,
        call_names=resolved,
        strings=strings,
        constants=list(constants_seen),
    )


_IMPORT_HINT_RE = re.compile(
    r"^(memcpy|memset|memmove|strcpy|strncpy|strcat|strcmp|strlen|sprintf|snprintf|printf|"
    r"puts|puts|malloc|calloc|realloc|free|read|write|open|close|recv|recvfrom|recvmsg|send|"
    r"socket|bind|listen|accept|connect|fopen|fclose|fread|fwrite|fgets|system|popen|execve|"
    r"setuid|rand|srand|exit|abort|atoi|atol|bcopy|hton|ntoh)"
)


def _looks_import(name: str) -> bool:
    """Heuristic: lowercase C-library-looking names are treated as external calls."""
    return (
        name.islower()
        and not name.startswith(("f", "g", "l", "p"))
        and bool(_IMPORT_HINT_RE.match(name))
    )


def normalize_image(ir_list: list[FunctionIR]) -> dict[str, NormalizedFunction]:
    """Normalize a whole image: build global maps, then normalize each function.

    Mutates ``ir.pseudocode_norm``, ``h_exact``, ``h_struct``, ``calls_out``,
    ``calls_in``, ``strings``, ``constants``, ``imports_called`` on each FunctionIR and
    returns the NormalizedFunction objects keyed by function id.
    """
    maps = ImageNameMaps.build([fn.pseudocode_raw for fn in ir_list])

    # FUN_hex name -> session function id (Ghidra names unambiguous within an image)
    fun_name_to_id = {fn.name: fn.id for fn in ir_list if _FUN_RE.match(fn.name)}

    out: dict[str, NormalizedFunction] = {}
    for fn in ir_list:
        norm = normalize_function(fn.pseudocode_raw, maps, image_fun_ids=fun_name_to_id)
        fn.pseudocode_norm = norm.text_exact
        fn.h_exact = norm.h_exact
        fn.h_struct = norm.h_struct
        fn.calls_out = [c for c in norm.call_names if c != fn.id]  # drop self-reference
        fn.strings = norm.strings
        fn.constants = norm.constants
        fn.imports_called = sorted({c for c in norm.call_names if c.startswith("IMPORT_")})
        out[fn.id] = norm

    # reverse call edges
    for fn in ir_list:
        fn.calls_in = []
    for fn in ir_list:
        for callee in fn.calls_out:
            callee_fn = next((f for f in ir_list if f.id == callee), None)
            if callee_fn is not None and fn.id not in callee_fn.calls_in:
                callee_fn.calls_in.append(fn.id)
    return out


def count_tokens(text: str) -> Counter[str]:
    return Counter(_TOKEN_RE.findall(text))
