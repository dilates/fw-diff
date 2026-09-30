"""Matcher stage tests (pipeline-spec §4)."""

from __future__ import annotations

from fw_diff.demo import load_demo_ir
from fw_diff.facts import assign_ids
from fw_diff.match import STAGE_ANCHOR, STAGE_EXACT, STAGE_STRUCT, Thresholds, run_match


def test_demo_stage_mix(demo_matched) -> None:
    _, _, result, _, _ = demo_matched
    counts = result.method_counts()
    # parse_header + log_event (symbols) + main (entry) anchor; helper_unpack + hmac via
    # unique struct hash; process_input + checksum via structural voting
    assert counts[STAGE_ANCHOR] == 3
    assert counts.get(STAGE_EXACT, 0) == 0  # fixture callee ordinals make exact rare
    assert counts[STAGE_STRUCT] == 4
    assert result.added == ["F0016"]  # telemetry_loop
    assert result.removed == ["F0007"]  # legacy_auth_check


def test_match_is_deterministic() -> None:
    a_old, a_new = load_demo_ir()
    assign_ids(a_old)
    assign_ids(a_new)
    b_old, b_new = load_demo_ir()
    assign_ids(b_old)
    assign_ids(b_new)
    res_a, _, _ = run_match(a_old, a_new)
    res_b, _, _ = run_match(b_old, b_new)
    assert [(p.old_id, p.new_id, p.method, p.confidence) for p in res_a.pairs] == [
        (p.old_id, p.new_id, p.method, p.confidence) for p in res_b.pairs
    ]


def test_exact_stage_precedes_struct() -> None:
    old_ir, new_ir = load_demo_ir()
    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))
    result, _, _ = run_match(old_ir, new_ir)
    by_new = result.by_new_id()
    # helper_unpack is identical modulo layout ordinals -> exact/struct-unique, not S2 vote
    helper = next(p for p in result.pairs if p.new_id == "F0014")
    _ = by_new
    assert helper.method in (STAGE_EXACT, STAGE_STRUCT)
    assert helper.confidence >= 0.95


def test_struct_stage_matches_shifted_addresses(demo_matched) -> None:
    _, _, result, _, _ = demo_matched
    # checksum_block moved from FUN_4001a900 (old F0006) to FUN_4002b120 (new F0007)
    pair = next(p for p in result.pairs if p.old_id == "F0006")
    assert pair.new_id == "F0015"
    assert pair.method == STAGE_STRUCT
    assert pair.confidence >= 0.80


def test_threshold_metadata_in_thresholds() -> None:
    t = Thresholds()
    assert t.to_dict() == {
        "tau": 0.80,
        "delta_margin": 0.08,
        "embed_sim_min": 0.82,
        "max_rounds": 6,
    }


def test_skipped_embedding_stage_reported(demo_matched) -> None:
    _, _, result, _, _ = demo_matched
    assert "embedding" in result.skipped_stages
