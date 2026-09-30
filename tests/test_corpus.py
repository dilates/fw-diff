"""Corpus cases in IR-fixture mode (testing-strategy §3): expect.json vs demo IR pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fw_diff.demo import load_demo_ir
from fw_diff.facts import assign_ids
from fw_diff.models import FunctionIR, ImageManifest
from fw_diff.pipeline import PipelineOptions, run_from_ir

CORPUS = Path(__file__).parent / "corpus"
# the committed demo IR pair is the lifted IR of the bounds-fix case (see corpus README)
CASE_TO_FIXTURE = {"bounds-fix": ("demo/fw-1.4.2.bin", "demo/fw-1.4.3.bin")}


def _ir(
    name: str,
    addr: int,
    image: str,
    code: str,
    params: int = 1,
    imports: list[str] | None = None,
    entry: bool = False,
) -> FunctionIR:
    return FunctionIR(
        id="",
        image=image,
        name=name,
        arch="armv7",
        addr=addr,
        size=len(code) * 4,
        params=params,
        entry=entry,
        pseudocode_raw=code,
        imports_called=imports or [],
    )


def _synthetic_pair(case: str) -> tuple[list[FunctionIR], list[FunctionIR]]:
    """In-test synthetic IR pairs for cases that are pure pipeline fixtures."""
    main_code = (
        "undefined4 FUN_1000(int param_1,int param_2)\n{\n"
        '  FUN_2000("%s: fw %s\\n","main","9.9.9");\n'
        "  return FUN_3000(1);\n}"
    )
    if case == "crypto-swap":

        def hmac(name: str, const: str) -> str:
            return (
                f"int {name}(int param_1,int param_2,int param_3)\n{{\n"
                f"  undefined4 local_20;\n  local_20 = {const};\n"
                f"  FUN_3000(param_1,param_2,&local_20);\n  return 0;\n}}"
            )

        old = [
            _ir("FUN_1000", 0x1000, "old", main_code, 2, entry=True),
            _ir("FUN_2000", 0x2000, "old", hmac("FUN_2000", "0x428a2f98"), 3),
            _ir(
                "FUN_3000",
                0x3000,
                "old",
                "void FUN_3000(int param_1,int param_2,int param_3)\n{\n  return;\n}",
                3,
            ),
        ]
        new = [
            _ir("FUN_1000", 0x1000, "new", main_code, 2, entry=True),
            _ir("FUN_2000", 0x2000, "new", hmac("FUN_2000", "0xdeadbeef"), 3),
            _ir(
                "FUN_3000",
                0x3000,
                "new",
                "void FUN_3000(int param_1,int param_2,int param_3)\n{\n  return;\n}",
                3,
            ),
        ]
        return old, new
    if case == "new-feature":
        old = [
            _ir("FUN_1000", 0x1000, "old", main_code, 2, entry=True),
            _ir(
                "FUN_2000", 0x2000, "old", "int FUN_2000(int param_1)\n{\n  return param_1 + 1;\n}"
            ),
        ]
        new = [
            _ir("FUN_1000", 0x1000, "new", main_code, 2, entry=True),
            _ir(
                "FUN_2000", 0x2000, "new", "int FUN_2000(int param_1)\n{\n  return param_1 + 1;\n}"
            ),
            _ir(
                "FUN_4000",
                0x4000,
                "new",
                'void FUN_4000(void)\n{\n  FUN_2000("/dev/mcu0");\n  return;\n}',
                0,
            ),
        ]
        return old, new
    if case == "dead-function-removed":
        old = [
            _ir("FUN_1000", 0x1000, "old", main_code, 2, entry=True),
            _ir(
                "FUN_2000",
                0x2000,
                "old",
                "int FUN_2000(int param_1)\n{\n  recv(param_1,0,0x100,0);\n"
                "  FUN_3000(param_1);\n  return 0;\n}",
                1,
                ["recv"],
            ),
            _ir("FUN_3000", 0x3000, "old", "void FUN_3000(int param_1)\n{\n  return;\n}"),
        ]
        new = [
            _ir("FUN_1000", 0x1000, "new", main_code, 2, entry=True),
            _ir(
                "FUN_2000",
                0x2000,
                "new",
                "int FUN_2000(int param_1)\n{\n  recv(param_1,0,0x100,0);\n  return 0;\n}",
                1,
                ["recv"],
            ),
        ]
        return old, new
    raise KeyError(case)


def _run_case(case: str, tmp_path: Path):
    if case in CASE_TO_FIXTURE:
        old_ir, new_ir = load_demo_ir()
        old_name, new_name = CASE_TO_FIXTURE[case]
    else:
        old_ir, new_ir = _synthetic_pair(case)
        old_name, new_name = f"synthetic/{case}-v1", f"synthetic/{case}-v2"
    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))
    return run_from_ir(
        old_ir,
        new_ir,
        PipelineOptions(out_dir=tmp_path / "out", deterministic=True),
        old_manifest=ImageManifest(path=old_name, sha256="corpus-old"),
        new_manifest=ImageManifest(path=new_name, sha256="corpus-new"),
    ).facts


@pytest.mark.corpus
@pytest.mark.parametrize("case", sorted(p.name for p in CORPUS.iterdir() if p.is_dir()))
def test_corpus_expectations(case: str, tmp_path: Path) -> None:
    expect = json.loads((CORPUS / case / "expect.json").read_text())
    doc = _run_case(case, tmp_path)

    for rule in expect.get("must_tag", []):
        tag = rule["classifier"]
        fn_name = rule["function"]
        hits = [c for c in doc.changes if tag in {t.tag for t in c.tags} and fn_name == c.new_name]
        assert hits, (
            f"{case}: expected {tag} on {fn_name}, got "
            f"{[(c.new_name, [t.tag for t in c.tags]) for c in doc.changes]}"
        )
        if "relevance" in rule:
            assert hits[0].relevance.score == rule["relevance"]

    for rule in expect.get("must_not_tag", []):
        tag = rule["classifier"]
        fn_name = rule["function"]
        offenders = [
            c.id for c in doc.changes if tag in {t.tag for t in c.tags} and fn_name == c.new_name
        ]
        assert not offenders, f"{case}: unexpected {tag} on {fn_name}: {offenders}"

    for key in expect.get("summary", {}):
        assert doc.summary[key] == expect["summary"][key]
