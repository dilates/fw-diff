"""Policy engine tests (exit semantics + rule DSL)."""

from __future__ import annotations

import textwrap

import pytest

from fw_diff.policy import PolicyError, evaluate_policy, load_policy


def _write_policy(tmp_path, content: str):
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(content))
    return load_policy(str(p))


def test_load_and_evaluate(tmp_path, demo_matched) -> None:
    policy = _write_policy(
        tmp_path,
        """\
        fail_on:
          - classifier: bound_change
            where: security_relevance == high
          - classifier: crypto_constant_change
        warn_on:
          - string_change
        """,
    )
    from fw_diff.models import ImageManifest
    from fw_diff.pipeline import PipelineOptions, run_from_ir

    old_ir, new_ir, _result, _old_norm, _new_norm = demo_matched
    doc = run_from_ir(
        old_ir,
        new_ir,
        PipelineOptions(out_dir=tmp_path / "out", deterministic=True),
        old_manifest=ImageManifest(path="a", sha256="a"),
        new_manifest=ImageManifest(path="b", sha256="b"),
    ).facts
    decision = evaluate_policy(doc, policy)
    assert decision.exit_code == 1
    assert decision.failures  # bound_change@high + crypto hit
    assert decision.warnings  # string_change


def test_removed_function_rule(tmp_path, demo_matched) -> None:
    policy = _write_policy(
        tmp_path,
        """\
        fail_on:
          - removed_function:
              reachable_from_input: true
        """,
    )
    from fw_diff.models import ImageManifest
    from fw_diff.pipeline import PipelineOptions, run_from_ir

    old_ir, new_ir, _, _, _ = demo_matched
    doc = run_from_ir(
        old_ir,
        new_ir,
        PipelineOptions(out_dir=tmp_path / "out", deterministic=True),
        old_manifest=ImageManifest(path="a", sha256="a"),
        new_manifest=ImageManifest(path="b", sha256="b"),
    ).facts
    decision = evaluate_policy(doc, policy)
    assert decision.exit_code == 1
    assert decision.failures[0]["change_ids"] == ["F0007"]  # legacy_auth_check


def test_invalid_where_expression(tmp_path, demo_matched) -> None:
    policy = _write_policy(
        tmp_path,
        """\
        fail_on:
          - classifier: bound_change
            where: security_relevance >= high
        """,
    )
    from fw_diff.models import ImageManifest
    from fw_diff.pipeline import PipelineOptions, run_from_ir

    old_ir, new_ir, _, _, _ = demo_matched
    doc = run_from_ir(
        old_ir,
        new_ir,
        PipelineOptions(out_dir=tmp_path / "out", deterministic=True),
        old_manifest=ImageManifest(path="a", sha256="a"),
        new_manifest=ImageManifest(path="b", sha256="b"),
    ).facts
    with pytest.raises(PolicyError):
        evaluate_policy(doc, policy)


def test_unknown_section_rejected(tmp_path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("bogus: []\n")
    with pytest.raises(PolicyError):
        load_policy(str(p))


def test_bare_string_rule_is_classifier(tmp_path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text("fail_on:\n  - crypto_constant_change\n")
    policy = load_policy(str(p))
    assert policy["fail_on"] == ["crypto_constant_change"]
