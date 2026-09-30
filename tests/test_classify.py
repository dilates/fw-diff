"""Classifier + relevance rubric tests (pipeline-spec §5.4-5.5)."""

from __future__ import annotations

import pytest

from fw_diff.delta import diff_pair, filter_layout_noise
from fw_diff.facts import compute_changes
from fw_diff.models import Change, FunctionIR


def _run_delta(demo_matched, old_id: str, new_id: str) -> Change:
    old_ir, new_ir, result, old_norm, new_norm = demo_matched
    pair = next(p for p in result.pairs if p.old_id == old_id)
    delta = diff_pair(old_norm[old_id], new_norm[pair.new_id])
    edits = filter_layout_noise(delta.edits)
    old_map = {fn.id: fn for fn in old_ir}
    new_map = {fn.id: fn for fn in new_ir}
    return Change(
        id="CH0001",
        old_id=old_id,
        new_id=pair.new_id,
        old_name=old_map[old_id].name,
        new_name=new_map[pair.new_id].name,
        match_method=pair.method,
        match_confidence=pair.confidence,
        edits=edits,
    )


def test_bound_change_on_parse_header(demo_matched) -> None:
    from fw_diff.facts import _tag_pair

    old_ir, new_ir, result, _, _ = demo_matched
    change = _run_delta(demo_matched, "F0002", "F0010")
    old_map = {fn.id: fn for fn in old_ir}
    new_map = {fn.id: fn for fn in new_ir}
    _tag_pair(change, old_map["F0002"], new_map["F0010"], old_map, new_map, set(), set(), result)
    tags = {t.tag for t in change.tags}
    assert "bound_change" in tags
    assert "branch_insert" in tags
    assert change.relevance.score == "high"
    assert change.relevance.components["edit_class"] == 3
    assert change.hypotheses[0].cwe == "CWE-190"


def test_crypto_constant_change(demo_matched) -> None:
    from fw_diff.facts import _tag_pair

    old_ir, new_ir, result, _, _ = demo_matched
    change = _run_delta(demo_matched, "F0003", "F0011")
    old_map = {fn.id: fn for fn in old_ir}
    new_map = {fn.id: fn for fn in new_ir}
    _tag_pair(change, old_map["F0003"], new_map["F0011"], old_map, new_map, set(), set(), result)
    tags = {t.tag for t in change.tags}
    assert "crypto_constant_change" in tags
    assert "constant_change" in tags
    assert change.relevance.score == "medium"
    assert change.relevance.components["crypto"] == 2


def test_string_change_not_constant_change(demo_matched) -> None:
    from fw_diff.facts import _tag_pair

    old_ir, new_ir, result, _, _ = demo_matched
    change = _run_delta(demo_matched, "F0001", "F0009")
    old_map = {fn.id: fn for fn in old_ir}
    new_map = {fn.id: fn for fn in new_ir}
    _tag_pair(change, old_map["F0001"], new_map["F0009"], old_map, new_map, set(), set(), result)
    tags = {t.tag for t in change.tags}
    assert "string_change" in tags
    assert "constant_change" not in tags


def test_callee_rename_is_filtered_not_tagged(demo_matched) -> None:
    """checksum_block address shift: signature/callee ordinals must not produce tags."""
    change = _run_delta(demo_matched, "F0006", "F0015")
    tags = {t.tag for t in change.tags}
    assert "call_target_change" not in tags
    assert "constant_change" not in tags
    # the return-line change survives
    assert change.edits


def test_compute_changes_end_to_end(demo_matched) -> None:
    old_ir, new_ir, result, old_norm, new_norm = demo_matched
    out = compute_changes(old_ir, new_ir, result, old_norm, new_norm)
    changed_ids = {(c.old_id, c.new_id) for c in out.changes}
    # helper_unpack is identical modulo layout ordinals -> NOT a change
    assert ("F0008", "F0007") not in changed_ids
    # changed set: main, parse_header, hmac, process_input, checksum_block
    assert ("F0001", "F0009") in changed_ids
    assert ("F0002", "F0010") in changed_ids
    assert ("F0003", "F0011") in changed_ids
    assert ("F0005", "F0013") in changed_ids
    assert ("F0006", "F0015") in changed_ids
    assert len(out.changes) == 5
    assert out.changes[0].id == "CH0001"  # ordered by new-image address
    # removed legacy_auth_check is reachable from input (called by process_input)
    assert out.auth_old


def test_auth_surface_reachable() -> None:
    from fw_diff.classify import auth_surface_set

    ir = [
        FunctionIR(
            id="F0001",
            image="old",
            name="FUN_100",
            addr=0x100,
            imports_called=["IMPORT_recv"],
            calls_out=["F0002"],
            pseudocode_raw="void FUN_100(void){recv(a,b,c,d);FUN_200();}",
        ),
        FunctionIR(
            id="F0002",
            image="old",
            name="FUN_200",
            addr=0x200,
            calls_out=["F0003"],
            pseudocode_raw="void FUN_200(void){FUN_300();}",
        ),
        FunctionIR(
            id="F0003",
            image="old",
            name="FUN_300",
            addr=0x300,
            calls_out=[],
            pseudocode_raw="void FUN_300(void){}",
        ),
        FunctionIR(
            id="F0004",
            image="old",
            name="FUN_400",
            addr=0x400,
            calls_out=[],
            pseudocode_raw="void FUN_400(void){}",
        ),
    ]
    assert auth_surface_set(ir) == {"F0001", "F0002", "F0003"}


def test_signature_change_detected(demo_matched) -> None:
    old_ir, new_ir, result, old_norm, new_norm = demo_matched
    # synthesize a param-count change
    old_fn = next(fn for fn in old_ir if fn.id == "F0008")
    old_fn.params = 3
    out = compute_changes(old_ir, new_ir, result, old_norm, new_norm)
    change = next(c for c in out.changes if c.old_id == "F0008")
    assert any(t.tag == "signature_change" for t in change.tags)


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("bound+mem+auth", "high"),
        ("crypto+constant", "medium"),
        ("auth-only", "low"),
        ("no-tags", "low"),
    ],
)
def test_rubric_thresholds(scenario: str, expected: str, demo_matched) -> None:
    from fw_diff.classify import _relevance_and_hypotheses
    from fw_diff.models import Relevance, Tag

    old_ir, new_ir, result, _, _ = demo_matched
    old_map = {fn.id: fn for fn in old_ir}
    new_map = {fn.id: fn for fn in new_ir}
    change = Change(
        id="CH0001",
        old_id="F0002",
        new_id="F0010",
        old_name="FUN_4001a3c0",
        new_name="FUN_4001a3c0",
        match_method="exact_hash",
        match_confidence=1.0,
    )

    scenario_tags = {
        "bound+mem+auth": [Tag("bound_change", 0.9)],
        "crypto+constant": [Tag("crypto_constant_change", 0.8), Tag("constant_change", 0.85)],
        "auth-only": [Tag("auth_surface_change", 0.8)],
        "no-tags": [],
    }[scenario]
    dangerous = {"memcpy"} if scenario == "bound+mem+auth" else set()
    auth_new = {"F0010"} if scenario in ("bound+mem+auth", "auth-only") else set()
    rel, hyp = _relevance_and_hypotheses(
        change, scenario_tags, dangerous, new_map["F0010"], old_map["F0002"], set(), auth_new, False
    )
    _ = result
    assert isinstance(rel, Relevance)
    assert rel.score == expected
    assert hyp is not None
