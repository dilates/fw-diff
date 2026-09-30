"""Timeline mode (ROADMAP v0.3): diff N images as a consecutive-pair chain.

Each pair runs the full pipeline into its own subdirectory; an ``index.md`` aggregates
the deltas so a vendor's release train reads as one story.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .log import get_logger, stage
from .pipeline import PipelineOptions, PipelineResult, run_pipeline
from .render import render_markdown

log = get_logger("fw_diff.timeline")


@dataclass
class TimelineResult:
    legs: list[PipelineResult] = field(default_factory=list)
    pairs: list[tuple[str, str]] = field(default_factory=list)
    index_path: Path | None = None

    def summary_rows(self) -> list[dict[str, Any]]:
        rows = []
        for leg, (old, new) in zip(self.legs, self.pairs, strict=True):
            s = leg.facts.summary
            rows.append(
                {
                    "old": old,
                    "new": new,
                    "changed": s["changed"],
                    "added": s["added"],
                    "removed": s["removed"],
                    "high": s["security_relevance"]["high"],
                    "session": leg.session_id,
                }
            )
        return rows


def _index_markdown(result: TimelineResult) -> str:
    lines = ["# fw-diff timeline", ""]
    rows = result.summary_rows()
    total_high = sum(r["high"] for r in rows)
    lines.append(f"{len(rows)} legs · {total_high} high-relevance changes total")
    lines.append("")
    lines.append("| from | to | changed | added | removed | high | session |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in rows:
        lines.append(
            f"| {r['old']} | {r['new']} | {r['changed']} | {r['added']} | "
            f"{r['removed']} | {r['high']} | {r['session']} |"
        )
    lines.append("")
    lines.append("## Per-leg high-relevance changes")
    lines.append("")
    for leg, (old, new) in zip(result.legs, result.pairs, strict=True):
        highs = [c for c in leg.facts.changes if c.relevance.score == "high"]
        lines.append(f"### {old} → {new}")
        lines.append("")
        if not highs:
            lines.append("_none_")
        for change in highs:
            tags = ", ".join(t.tag for t in change.tags)
            lines.append(f"- `{change.id}` {change.new_name} — {tags}")
        lines.append("")
    return "\n".join(lines) + "\n"


def run_timeline(
    paths: list[Path],
    opts: PipelineOptions,
    *,
    policy: dict[str, Any] | None = None,
) -> TimelineResult:
    """Diff each consecutive pair (v1, v2), (v2, v3), … into ``opts.out_dir/pair-NN``."""
    if len(paths) < 2:
        raise ValueError("timeline needs at least two images")
    result = TimelineResult()
    with stage(log, "timeline", count=len(paths) - 1):
        for i in range(len(paths) - 1):
            old, new = paths[i], paths[i + 1]
            pair_dir = opts.out_dir / f"pair-{i + 1:02d}"
            pair_dir.mkdir(parents=True, exist_ok=True)
            leg_opts = PipelineOptions(
                arch=opts.arch,
                base=opts.base,
                out_dir=pair_dir,
                llm=opts.llm,
                deterministic=opts.deterministic,
                max_functions=opts.max_functions,
                jvm_heap=opts.jvm_heap,
                worker_mode=opts.worker_mode,
                map_pairs=opts.map_pairs,
                use_embeddings=opts.use_embeddings,
                embedder=opts.embedder,
                ghidra_dir=opts.ghidra_dir,
            )
            leg = run_pipeline(old, new, leg_opts, policy=policy)
            result.legs.append(leg)
            result.pairs.append((str(old), str(new)))
            log.info(
                "timeline leg done",
                extra={"stage": "timeline", "count": leg.facts.summary["changed"]},
            )
    opts.out_dir.mkdir(parents=True, exist_ok=True)
    index = opts.out_dir / "index.md"
    index.write_text(_index_markdown(result), encoding="utf-8")
    result.index_path = index
    return result


def render_leg_report(leg: PipelineResult) -> str:
    return render_markdown(leg.facts)
