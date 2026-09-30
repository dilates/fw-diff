"""Explainer guardrail tests: evidence validation, claim dropping, provider failure."""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from fw_diff.explain import ExplainConfig, ExplainError, _apply_batch
from fw_diff.facts import compute_changes
from fw_diff.models import ExplainBlock


class FakeProvider:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[str] = []

    def chat(self, url: str, model: str, system: str, user: str, timeout: int) -> str:
        self.calls.append(user)
        return self.response


def _opts():
    from pathlib import Path

    from fw_diff.pipeline import PipelineOptions

    return PipelineOptions(out_dir=Path("/tmp/opencode/x"), deterministic=True)


def test_valid_claims_kept_and_dropped_counted(demo_matched) -> None:
    old_ir, new_ir, result, old_norm, new_norm = demo_matched
    from fw_diff.facts import assign_ids, build_facts
    from fw_diff.models import ImageManifest, SessionInfo

    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))
    delta_out = compute_changes(old_ir, new_ir, result, old_norm, new_norm)
    doc = build_facts(
        SessionInfo(
            id="s",
            created_utc=None,
            old_manifest=ImageManifest(path="a", sha256="a"),
            new_manifest=ImageManifest(path="b", sha256="b"),
            config={},
        ),
        old_ir,
        new_ir,
        result,
        delta_out.changes,
        delta_out.auth_old,
        delta_out.auth_new,
    )
    change = doc.changes[0]
    good_evidence = [f"{change.id}.edit@1"]
    raw = json.dumps(
        {
            "changes": [
                {
                    "id": change.id,
                    "narrative": "A clamp was added.",
                    "confidence": "medium",
                    "claims": [
                        {"id": 1, "evidence": good_evidence},
                        {"id": 2, "evidence": ["FABRICATED.evidence@9"]},
                    ],
                }
            ]
        }
    )
    dropped = _apply_batch(doc, [change], raw, ExplainConfig(provider="off"))
    assert dropped == 1
    assert change.explain is not None
    assert change.explain.provenance["dropped_claims"] == 1
    assert change.explain.claims[0]["evidence"] == good_evidence


def test_unparseable_output_drops_batch(demo_matched) -> None:
    old_ir, new_ir, result, old_norm, new_norm = demo_matched
    from fw_diff.facts import assign_ids, build_facts, compute_changes
    from fw_diff.models import ImageManifest, SessionInfo

    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))
    delta_out = compute_changes(old_ir, new_ir, result, old_norm, new_norm)
    doc = build_facts(
        SessionInfo(
            id="s",
            created_utc=None,
            old_manifest=ImageManifest(path="a", sha256="a"),
            new_manifest=ImageManifest(path="b", sha256="b"),
            config={},
        ),
        old_ir,
        new_ir,
        result,
        delta_out.changes,
        delta_out.auth_old,
        delta_out.auth_new,
    )
    dropped = _apply_batch(doc, doc.changes[:2], "not json at all", ExplainConfig(provider="off"))
    assert dropped >= 1
    assert all(c.explain is None for c in doc.changes[:2])


def test_off_provider_is_noop(demo_matched) -> None:
    old_ir, new_ir, result, old_norm, new_norm = demo_matched
    from fw_diff.facts import assign_ids, build_facts, compute_changes
    from fw_diff.models import ImageManifest, SessionInfo

    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))
    delta_out = compute_changes(old_ir, new_ir, result, old_norm, new_norm)
    doc = build_facts(
        SessionInfo(
            id="s",
            created_utc=None,
            old_manifest=ImageManifest(path="a", sha256="a"),
            new_manifest=ImageManifest(path="b", sha256="b"),
            config={},
        ),
        old_ir,
        new_ir,
        result,
        delta_out.changes,
        delta_out.auth_old,
        delta_out.auth_new,
    )
    explained, dropped = _noop_explain(doc)
    assert explained == 0 and dropped == 0
    assert all(c.explain is None for c in doc.changes)


def _noop_explain(doc: object) -> tuple[int, int]:
    from fw_diff.explain import explain_facts
    from fw_diff.models import FactsDoc

    assert isinstance(doc, FactsDoc)
    empty_new: dict[str, Any] = {}
    from fw_diff.normalize import NormalizedFunction

    _ = NormalizedFunction
    return explain_facts(doc, empty_new, {}, ExplainConfig(provider="off"))


def test_prompt_contract_mentions_evidence_and_data_fences() -> None:
    from fw_diff.explain import _SYSTEM_PROMPT, PROMPT_VERSION

    assert "evidence" in _SYSTEM_PROMPT
    assert "DATA" in _SYSTEM_PROMPT
    assert PROMPT_VERSION == "pv1"


def test_explain_error_wraps_provider_failure() -> None:
    with pytest.raises(ExplainError):
        ExplainConfig(provider="openai-compat").resolved_url()  # no url -> error


def test_explain_block_serialization() -> None:
    block = ExplainBlock(
        narrative="x",
        confidence="low",
        claims=[{"id": 1, "evidence": ["a"]}],
        provenance={"model": "m", "prompt_version": "pv1", "dropped_claims": 0},
    )
    assert block.to_dict()["provenance"]["dropped_claims"] == 0


def test_urlopen_failure_becomes_explain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from fw_diff.explain import _chat

    def boom(*args: object, **kwargs: object) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(ExplainError):
        _chat("http://127.0.0.1:1/v1", "m", "s", "u", None, 1)
