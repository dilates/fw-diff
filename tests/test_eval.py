"""Explainer eval harness (ROADMAP v0.2, testing-strategy §5).

Runs nightly (marker ``eval``) against a local Ollama model on the corpus fixture pair.
Graded: factuality (claims must cite resolvable evidence — enforced by the pipeline
itself), coverage (share of changes explained), and correctness (expected keywords per
ground-truth case). Scores written to docs/evals/latest.json.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

import pytest

from fw_diff.demo import load_demo_ir
from fw_diff.explain import DEFAULT_OLLAMA_URL
from fw_diff.facts import assign_ids
from fw_diff.models import ImageManifest
from fw_diff.pipeline import PipelineOptions, run_from_ir

pytestmark = pytest.mark.eval

# ground truth per change (we wrote the fixtures): narrative must contain a keyword
GROUND_TRUTH = {
    "FUN_400000d0": ["1.4.2", "1.4.3"],  # version bump
    "FUN_4001a3c0": ["0x40", "bound", "clamp", "limit", "size", "64"],  # bounds fix
    "FUN_4001a5e0": ["constant", "hash", "sha", "hmac", "crypto"],  # crypto constant
    "FUN_4001a810": ["call", "removed", "auth", "legacy"],  # legacy call removed
    "FUN_4002b120": ["return", "xor", "not", "~", "checksum", "bitwise"],  # return change
}


def _ollama_reachable() -> bool:
    for path in ("/v1/models", "/api/tags"):
        try:
            urllib.request.urlopen(f"{DEFAULT_OLLAMA_URL.removesuffix('/v1')}{path}", timeout=3)
            return True
        except OSError:
            continue
    return False


def _model() -> str:
    return os.environ.get("FW_DIFF_EVAL_MODEL", "qwen3:4b")


@pytest.fixture()
def explained_doc(tmp_path: Path):
    old_ir, new_ir = load_demo_ir()
    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))
    opts = PipelineOptions(
        out_dir=tmp_path / "out",
        deterministic=True,
        llm=__import__("fw_diff.explain", fromlist=["ExplainConfig"]).ExplainConfig(
            provider="ollama", model=_model()
        ),
    )
    return run_from_ir(
        old_ir,
        new_ir,
        opts,
        old_manifest=ImageManifest(path="corpus/bounds-fix/v1.bin", sha256="a"),
        new_manifest=ImageManifest(path="corpus/bounds-fix/v2.bin", sha256="b"),
    ).facts


@pytest.mark.skipif(not _ollama_reachable(), reason="local Ollama not reachable")
def test_eval_factuality_and_coverage(explained_doc, tmp_path: Path) -> None:
    changes = explained_doc.changes
    explained = [c for c in changes if c.explain is not None]

    # factuality: pipeline already drops unresolvable claims; zero fabricated tolerated
    fabricated = 0
    for change in explained:
        allowed = {f"{change.id}.edit@{i}" for i in range(1, len(change.edits) + 1)}
        allowed |= {f"{change.id}.classifiers@{i}" for i in range(len(change.tags))}
        for claim in change.explain.claims:
            if not all(e in allowed for e in claim.get("evidence", [])):
                fabricated += 1
    assert fabricated == 0, "explainer fabricated evidence — factuality gate failed"

    # correctness: narrative mentions at least one ground-truth keyword
    correct = 0
    for change in explained:
        keys = GROUND_TRUTH.get(change.new_name, [])
        text = change.explain.narrative.lower()
        if any(k.lower() in text for k in keys):
            correct += 1

    coverage = len(explained) / max(len(changes), 1)
    correctness = correct / max(len(explained), 1)
    scores = {
        "model": _model(),
        "changes": len(changes),
        "explained": len(explained),
        "coverage": round(coverage, 3),
        "correctness": round(correctness, 3),
        "factuality_violations": fabricated,
        "gate": coverage >= 0.5 and correctness >= 0.5 and fabricated == 0,
    }
    out_dir = Path(__file__).parent.parent / "docs" / "evals"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps(scores, indent=2, sort_keys=True) + "\n")
    assert scores["gate"], f"eval below gate: {scores}"
