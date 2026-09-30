"""Ghidra lift backend (ADR-0002): PyGhidra in-process, Ghidra 11.3+.

Produces raw function records (Ghidra names; call targets as raw names) — id assignment and
call resolution happen in the pipeline. Requires ``pip install 'fw-diff[ghidra]'`` and
``GHIDRA_INSTALL_DIR`` pointing at Ghidra 11.3+ (tested against 11.3.2, Java 21).

Honest failure (ARCHITECTURE §8): functions that fail to decompile are skipped and counted;
regions are surfaced as lift gaps in reports (per-region tracking lands in v0.2).
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .log import get_logger
from .models import FunctionIR

log = get_logger("fw_diff.ghidra")

LANG_IDS: dict[str, str] = {
    "armv7": "ARM:LE:32:default",
    "aarch64": "AARCH64:LE:64:default",
    "mipsel": "MIPS:LE:32:default",
    "mips": "MIPS:BE:32:default",
    "riscv64": "RISC-V:LE:64:default",
    "riscv32": "RISC-V:LE:32:default",
    "x86": "x86:LE:32:default",
    "x86_64": "x86:LE:64:default",
    "ppc": "PowerPC:BE:32:default",
    "ppc64": "PowerPC:BE:64:default",
}

FUN_NAME_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")


class LiftError(RuntimeError):
    pass


@dataclass
class LiftOutput:
    functions: list[FunctionIR] = field(default_factory=list)
    ghidra_version: str | None = None
    skipped_functions: int = 0
    lift_gaps: list[dict[str, object]] = field(default_factory=list)


def _ghidra_dir(explicit: str | None) -> Path:
    cand = Path(explicit or os.environ.get("GHIDRA_INSTALL_DIR", ""))
    if cand.is_dir():
        return cand
    for pattern in ("/opt/ghidra*", str(Path.home() / "re" / "ghidra_*")):
        hits = sorted(glob.glob(pattern))
        if hits:
            return Path(hits[0])
    raise LiftError(
        "Ghidra not found: set GHIDRA_INSTALL_DIR to a Ghidra 11.3+ install (tested against 11.3.2)"
    )


def _ghidra_version(ghidra_dir: Path) -> str:
    props = ghidra_dir / "Ghidra" / "application.properties"
    if props.exists():
        match = re.search(r"^application\.version=(.+)$", props.read_text(), re.MULTILINE)
        if match:
            return match.group(1).strip()
    return "unknown"


def _importish(name: str) -> bool:
    return name.islower() and not name.startswith(("FUN_", "DAT_", "f", "g"))


def resolve_calls(ir_list: list[FunctionIR]) -> None:
    """Turn raw call-target names into function ids / IMPORT_<name> entries."""
    by_name = {fn.name: fn.id for fn in ir_list}
    for fn in ir_list:
        fn.calls_out = [
            by_name[raw] if raw in by_name else (f"IMPORT_{raw}" if _importish(raw) else raw)
            for raw in fn.calls_out
        ]
    for fn in ir_list:
        fn.calls_in = []
    id_map = {fn.id: fn for fn in ir_list}
    for fn in ir_list:
        for callee in fn.calls_out:
            callee_fn = id_map.get(callee)
            if callee_fn is not None and fn.id not in callee_fn.calls_in:
                callee_fn.calls_in.append(fn.id)


def lift_image(
    target_path: str,
    *,
    arch: str | None = None,
    base: int | None = None,
    workdir: str | None = None,
    max_functions: int | None = None,
    jvm_heap: str | None = None,
    ghidra_dir: str | None = None,
) -> LiftOutput:
    """Lift one binary via PyGhidra; raw flat binaries require ``base`` (+ ``arch``)."""
    try:
        import pyghidra
    except ImportError as exc:
        raise LiftError(
            "pyghidra is not installed: pip install 'fw-diff[ghidra]' "
            "(or run inside the fw-diff-worker container, v0.2)"
        ) from exc

    gh = _ghidra_dir(ghidra_dir)
    version = _ghidra_version(gh)
    os.environ["GHIDRA_INSTALL_DIR"] = str(gh)
    if jvm_heap:
        os.environ["_JAVA_OPTIONS"] = f"-Xmx{jvm_heap}"

    work = Path(workdir or ".")
    proj = work / "ghidra_proj"
    proj.mkdir(parents=True, exist_ok=True)

    raw_mode = base is not None
    if raw_mode and arch not in LANG_IDS:
        raise LiftError(
            f"raw flat binary lift requires a known arch (--arch); got {arch!r}. "
            f"Known: {sorted(LANG_IDS)}"
        )
    kwargs: dict[str, object] = {
        "project_location": proj,
        "project_name": "fw_diff_lift",
        # raw mode: analyze after setImageBase (base must be applied first)
        "analyze": not raw_mode,
    }
    if raw_mode:
        kwargs["language"] = LANG_IDS[arch]  # type: ignore[index]
        kwargs["loader"] = "ghidra.app.util.opinion.BinaryLoader"  # Ghidra's Raw Binary

    functions: list[FunctionIR] = []
    skipped = 0
    gaps: list[dict[str, object]] = []
    try:
        pyghidra.start()
        with pyghidra.open_program(target_path, **kwargs) as flat:
            program = flat.getCurrentProgram()
            if raw_mode:
                _apply_raw_base(
                    flat,
                    program,
                    int(base),  # type: ignore[arg-type]
                    os.path.getsize(str(target_path)),
                )
            skipped, gaps = _lift_program(program, functions, max_functions)
    except LiftError:
        raise
    except Exception as exc:  # JVM/Ghidra errors surface as LiftError (honest failure)
        raise LiftError(f"Ghidra lift failed: {exc}") from exc

    resolve_calls(functions)
    out = LiftOutput(
        functions=functions, ghidra_version=version, skipped_functions=skipped, lift_gaps=gaps
    )
    for fn in out.functions:
        fn.meta["ghidra"] = version
        fn.meta["strings_extracted"] = "regex"
    return out


def _apply_raw_base(flat: Any, program: Any, base: int, size: int) -> None:
    """Set the image base, run analysis, and seed an ``entry`` function covering the
    payload if Ghidra found none (raw blobs have no entry-point metadata)."""
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.symbol import SourceType

    af = program.getAddressFactory().getDefaultAddressSpace().getAddress(base)
    program.setImageBase(af, True)
    flat.analyzeAll(program)
    fm = program.getFunctionManager()
    if not any(fm.getFunctions(True)):
        flat.disassemble(af)
        body = AddressSet(af, af.add(max(size - 1, 0)))
        try:
            fm.createFunction("entry", af, body, SourceType.USER_DEFINED)
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("entry seeding failed: %s", exc)


def _lift_program(
    program: Any, functions: list[FunctionIR], max_functions: int | None
) -> tuple[int, list[dict[str, object]]]:
    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(program)

    fm = program.getFunctionManager()
    arch = _detect_arch(program)

    skipped = 0
    gaps: list[dict[str, object]] = []
    count = 0
    for fn in fm.getFunctions(True):
        if fn.isThunk() or fn.isExternal():
            continue
        if max_functions is not None and count >= max_functions:
            break
        result = ifc.decompileFunction(fn, 120, monitor)
        if not result.decompileCompleted():
            skipped += 1
            addr = fn.getEntryPoint().getOffset()
            gaps.append({"addr": int(addr), "reason": "decompile_failed"})
            continue
        code = str(result.getDecompiledFunction().getC())
        name = str(fn.getName())
        addr = int(fn.getEntryPoint().getOffset())
        params = len(list(fn.getParameters()))
        body = int(fn.getBody().getNumAddresses())
        is_entry = bool(fn.getSymbol().isExternalEntryPoint())
        symbols = [] if FUN_NAME_RE.match(name) else [name]
        calls_out: list[str] = []
        for callee in fn.getCalledFunctions(monitor):
            cname = str(callee.getName())
            if cname != name and cname not in calls_out:
                calls_out.append(cname)
        functions.append(
            FunctionIR(
                id="",
                image="",
                name=name,
                symbols=symbols,
                arch=arch,
                addr=addr,
                size=body,
                params=params,
                entry=is_entry,
                pseudocode_raw=code,
                calls_out=calls_out,
            )
        )
        count += 1
    ifc.closeProgram()
    return skipped, gaps


def _detect_arch(program: Any) -> str:
    try:
        lid = str(program.getLanguageID())  # e.g. "ARM:LE:32:v7"
        parts = lid.split(":")
        head, size = parts[0].lower(), parts[2] if len(parts) > 2 else ""
        mapping = {
            "arm": "armv7",
            "aarch64": "aarch64",
            "mips": "mips" if size == "32" else "mips64",
            "riscv": f"riscv{size}",
            "x86": "x86_64" if size == "64" else "x86",
            "powerpc": "ppc" if size == "32" else "ppc64",
        }
        return mapping.get(head, head)
    except Exception:  # pragma: no cover - defensive
        return "unknown"
