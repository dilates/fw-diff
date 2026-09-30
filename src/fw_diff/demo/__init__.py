"""Demo fixtures: two small fixture images (IR-level) for a zero-setup end-to-end run.

`fw-diff demo` runs the full deterministic pipeline on these — no Ghidra, no binaries
needed (the lift stage is replaced by loading the fixture IR). Useful for first contact,
CI, and reproducibility checks.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from ..models import FunctionIR


def load_demo_ir() -> tuple[list[FunctionIR], list[FunctionIR]]:
    old = _load("old_ir.json")
    new = _load("new_ir.json")
    for fn in old:
        fn.image = "old"
    for fn in new:
        fn.image = "new"
    return old, new


def _load(name: str) -> list[FunctionIR]:
    text = (resources.files("fw_diff.demo") / name).read_text(encoding="utf-8")
    return [FunctionIR.from_dict(d) for d in json.loads(text)]


def demo_paths() -> tuple[Path, Path]:
    root = resources.files("fw_diff.demo")
    return Path(str(root / "old_ir.json")), Path(str(root / "new_ir.json"))
