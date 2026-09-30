"""Normalization golden tests (pipeline-spec §3 is normative)."""

from __future__ import annotations

import pytest

from fw_diff.models import FunctionIR
from fw_diff.normalize import ImageNameMaps, normalize_function, normalize_image


def _norm(text: str) -> object:
    maps = ImageNameMaps.build([text])
    return normalize_function(text, maps)


def test_deterministic_repeated_calls() -> None:
    text = "int FUN_1000(void)\n{\n  return DAT_2000;\n}"
    a, b = _norm(text), _norm(text)  # type: ignore[operator]
    assert a.h_exact == b.h_exact  # type: ignore[attr-defined]
    assert a.h_struct == b.h_struct  # type: ignore[attr-defined]


def test_fun_map_ordered_by_address() -> None:
    text = "void f(void)\n{\n  FUN_40000020();\n  FUN_40000010();\n}"
    maps = ImageNameMaps.build([text])
    assert maps.fun_map["FUN_40000010"] == "f1"
    assert maps.fun_map["FUN_40000020"] == "f2"


def test_locals_first_appearance() -> None:
    text = "int f(void)\n{\n  int uVar2;\n  int uVar1;\n  uVar1 = 1;\n  uVar2 = 2;\n  return uVar1 + uVar2;\n}"
    norm = _norm(text)
    # first-appearance order: uVar2 declared first -> l1, uVar1 -> l2 (spec §3.1)
    assert "l2 = 1" in norm.text_exact  # type: ignore[attr-defined]
    assert "l1 = 2" in norm.text_exact  # type: ignore[attr-defined]
    assert "uVar1" not in norm.text_exact  # type: ignore[attr-defined]


def test_params_canonicalized() -> None:
    norm = _norm("int f(int param_1,int param_2)\n{\n  return param_1 + param_2;\n}")
    assert "p1 + p2" in norm.text_exact  # type: ignore[attr-defined]


def test_constant_buckets() -> None:
    norm = _norm(
        "void f(void)\n{\n  g(0x40);\n  g(0x1234);\n  g(0x12345678);\n  g(0x100000000);\n}"
    )
    assert norm.h_exact != norm.h_struct  # type: ignore[attr-defined]
    st = norm.text_struct  # type: ignore[attr-defined]
    assert "C1" in st and "C2" in st and "C4" in st and "C8" in st


def test_struct_hash_ignores_constant_values() -> None:
    a = _norm("void f(void)\n{\n  g(0x40);\n}")
    b = _norm("void f(void)\n{\n  g(0x80);\n}")
    assert a.h_exact != b.h_exact  # type: ignore[attr-defined]
    assert a.h_struct == b.h_struct  # type: ignore[attr-defined]


def test_struct_hash_neutralizes_cross_image_ids() -> None:
    # f<ord>/g<ord> are image-layout artifacts; the struct view must not see them
    a = _norm("void f(void)\n{\n  FUN_40000010(DAT_40000020);\n}")
    b = _norm("void f(void)\n{\n  FUN_90000030(DAT_90000040);\n}")
    assert a.h_struct == b.h_struct  # type: ignore[attr-defined]
    assert "FCALL" in a.text_struct and "GDATA" in a.text_struct  # type: ignore[attr-defined]


def test_exact_hash_is_layout_dependent_by_design() -> None:
    """Same caller text, different image layouts -> different callee ordinals ->
    h_exact differs (exact stage is genuinely exact); h_struct still equal."""
    src = "void FUN_100(void)\n{\n  FUN_300();\n}"
    other1 = "void FUN_200(void)\n{\n}"
    other2 = "void FUN_300(void)\n{\n}"
    maps_full = ImageNameMaps.build([src, other1, other2])  # FUN_300 -> f3
    maps_slim = ImageNameMaps.build([src, other2])  # FUN_300 -> f2
    a = normalize_function(src, maps_full)
    b = normalize_function(src, maps_slim)
    assert a.h_exact != b.h_exact
    assert a.h_struct == b.h_struct


def test_string_length_bucketing() -> None:
    a = _norm('void f(void)\n{\n  log("hello");\n}')
    b = _norm('void f(void)\n{\n  log("world");\n}')
    assert a.h_exact != b.h_exact  # type: ignore[attr-defined]
    assert a.h_struct == b.h_struct  # type: ignore[attr-defined]


def test_preserved_names_survive() -> None:
    norm = _norm("int parse_header(int param_1)\n{\n  return memcpy(param_1,param_1,4);\n}")
    assert "memcpy" in norm.text_exact  # type: ignore[attr-defined]
    assert "parse_header" in norm.text_exact  # type: ignore[attr-defined]


def test_calls_resolved_to_ids_and_imports() -> None:
    ir = [
        FunctionIR(
            id="F0001",
            image="old",
            name="FUN_100",
            addr=0x100,
            pseudocode_raw="void FUN_100(void)\n{\n  FUN_200();\n}\n",
        ),
        FunctionIR(
            id="F0002",
            image="old",
            name="FUN_200",
            addr=0x200,
            pseudocode_raw="void FUN_200(void)\n{\n  memcpy(x,x,4);\n}\n",
        ),
    ]
    normalize_image(ir)
    assert ir[0].calls_out == ["F0002"]
    assert ir[1].calls_out == ["IMPORT_memcpy"]
    assert ir[1].calls_in == ["F0001"]


@pytest.mark.parametrize(
    ("value", "bucket"),
    [
        (0, "C1"),
        (255, "C1"),
        (256, "C2"),
        (65535, "C2"),
        (65536, "C4"),
        (0xFFFFFFFF, "C4"),
        (0x100000000, "C8"),
    ],
)
def test_bucket_boundaries(value: int, bucket: str) -> None:
    from fw_diff.normalize import _constant_bucket

    assert _constant_bucket(value) == bucket
