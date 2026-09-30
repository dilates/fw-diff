"""Pipeline orchestration: ingest → lift → normalize → match → delta → facts → explain →
render → (policy). One function per full run; granular steps are importable for tools."""

from __future__ import annotations

import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .explain import ExplainConfig, explain_facts
from .facts import assign_ids, build_facts, compute_changes, deterministic_session_id
from .ingest import ResourceCaps, choose_pair_targets, ingest
from .log import get_logger, stage
from .match import EmbeddingProvider, Thresholds, apply_manual_map, run_match
from .models import FactsDoc, FunctionIR, ImageManifest, LiftTarget, SessionInfo
from .policy import PolicyDecision, evaluate_policy
from .render import render_html, render_markdown
from .store import Store, sha256_bytes

log = get_logger("fw_diff.pipeline")


class PipelineError(RuntimeError):
    pass


@dataclass
class PipelineOptions:
    arch: str | None = None
    base: int | None = None
    out_dir: Path = field(default_factory=lambda: Path("out"))
    llm: ExplainConfig = field(default_factory=lambda: ExplainConfig(provider="off"))
    deterministic: bool = False
    max_functions: int | None = None
    jvm_heap: str | None = None
    worker_mode: str = "local"
    map_pairs: list[tuple[str, str]] = field(default_factory=list)
    embedder: EmbeddingProvider | None = None
    ghidra_dir: str | None = None


@dataclass
class PipelineResult:
    facts: FactsDoc
    policy: PolicyDecision | None
    artifacts: dict[str, Path]
    session_id: str


def _session_info(
    old: ImageManifest,
    new: ImageManifest,
    opts: PipelineOptions,
    thresholds: Thresholds,
    policy_sha: str | None,
) -> SessionInfo:
    config: dict[str, Any] = {
        "thresholds": thresholds.to_dict(),
        "llm": f"{opts.llm.provider}/{opts.llm.model}" if opts.llm.provider != "off" else "off",
        "deterministic": opts.deterministic,
        "policy_sha256": policy_sha,
        "worker_mode": opts.worker_mode,
    }
    if opts.deterministic:
        sid = deterministic_session_id(old.sha256, new.sha256)
        created = None
    else:
        sid = uuid.uuid4().hex[:16]
        created = datetime.now(UTC).isoformat(timespec="seconds")
    return SessionInfo(
        id=sid, created_utc=created, old_manifest=old, new_manifest=new, config=config
    )


def _lift_both(
    old_target: LiftTarget, new_target: LiftTarget, opts: PipelineOptions, workdir: Path
) -> tuple[list[FunctionIR], list[FunctionIR], str]:
    if opts.worker_mode == "docker":
        raise PipelineError(
            "worker-mode docker arrives in v0.2 (ROADMAP); use local mode or the CI "
            "fixture path for now"
        )
    from .ghidra_lift import lift_image

    with stage(log, "lift", count=2):
        old_out = lift_image(
            old_target.path,
            arch=old_target.arch,
            base=old_target.base,
            workdir=str(workdir / "lift_old"),
            max_functions=opts.max_functions,
            jvm_heap=opts.jvm_heap,
            ghidra_dir=opts.ghidra_dir,
        )
        new_out = lift_image(
            new_target.path,
            arch=new_target.arch,
            base=new_target.base,
            workdir=str(workdir / "lift_new"),
            max_functions=opts.max_functions,
            jvm_heap=opts.jvm_heap,
            ghidra_dir=opts.ghidra_dir,
        )
    if old_out.ghidra_version != new_out.ghidra_version:
        log.warning("ghidra versions differ between sides", extra={"count": 2})
    return old_out.functions, new_out.functions, old_out.ghidra_version or "unknown"


def run_from_ir(
    old_ir: list[FunctionIR],
    new_ir: list[FunctionIR],
    opts: PipelineOptions,
    *,
    old_manifest: ImageManifest | None = None,
    new_manifest: ImageManifest | None = None,
    ghidra_version: str | None = None,
    policy: dict[str, Any] | None = None,
) -> PipelineResult:
    """Full pipeline from already-lifted IR (demo/fixtures). Real runs go via run_pipeline."""
    store = Store()
    thresholds = Thresholds()
    old_manifest = old_manifest or ImageManifest(
        path="fixture-old",
        sha256=sha256_bytes(b"\n".join(fn.pseudocode_raw.encode() for fn in old_ir)),
    )
    new_manifest = new_manifest or ImageManifest(
        path="fixture-new",
        sha256=sha256_bytes(b"\n".join(fn.pseudocode_raw.encode() for fn in new_ir)),
    )

    assign_ids(old_ir)
    assign_ids(new_ir, offset=len(old_ir))
    match_result, old_norm, new_norm = run_match(
        old_ir, new_ir, embedder=opts.embedder, thresholds=thresholds
    )
    if opts.map_pairs:
        match_result = apply_manual_map(
            match_result, {fn.id: fn for fn in old_ir}, {fn.id: fn for fn in new_ir}, opts.map_pairs
        )

    delta_out = compute_changes(old_ir, new_ir, match_result, old_norm, new_norm)

    session = _session_info(old_manifest, new_manifest, opts, thresholds, _sha_of_policy(policy))
    doc = build_facts(
        session,
        old_ir,
        new_ir,
        match_result,
        delta_out.changes,
        delta_out.auth_old,
        delta_out.auth_new,
        ghidra_version=ghidra_version,
    )

    if opts.llm.provider != "off":
        new_map = {fn.id: fn for fn in new_ir}
        explained, _dropped = explain_facts(doc, new_map, new_norm, opts.llm)
        log.info("explain done", extra={"stage": "explain", "count": explained})

    opts.out_dir.mkdir(parents=True, exist_ok=True)
    artifacts = _render_all(doc, opts.out_dir)
    _persist(store, doc, old_ir, new_ir)
    decision = evaluate_policy(doc, policy) if policy else None
    return PipelineResult(facts=doc, policy=decision, artifacts=artifacts, session_id=session.id)


def run_pipeline(
    old_path: Path,
    new_path: Path,
    opts: PipelineOptions,
    *,
    policy: dict[str, Any] | None = None,
    caps_hard: bool = False,
) -> PipelineResult:
    """Full pipeline from two image files."""
    caps = ResourceCaps().harder() if caps_hard else ResourceCaps()
    with tempfile.TemporaryDirectory(prefix="fw-diff-") as tmp:
        workdir = Path(tmp)
        with stage(log, "ingest", count=2):
            old_manifest = ingest(
                Path(old_path), workdir / "ingest_old", caps, arch=opts.arch, base=opts.base
            )
            new_manifest = ingest(
                Path(new_path), workdir / "ingest_new", caps, arch=opts.arch, base=opts.base
            )
        old_target, new_target = choose_pair_targets(old_manifest, new_manifest)
        old_ir, new_ir, ghidra_version = _lift_both(old_target, new_target, opts, workdir)
        result = run_from_ir(
            old_ir,
            new_ir,
            opts,
            old_manifest=old_manifest,
            new_manifest=new_manifest,
            ghidra_version=ghidra_version,
            policy=policy,
        )
        return result


def _sha_of_policy(policy: dict[str, Any] | None) -> str | None:
    import hashlib
    import json

    if policy is None:
        return None
    return hashlib.sha256(
        json.dumps(policy, sort_keys=True, default=str).encode()).hexdigest()


def _render_all(doc: FactsDoc, out_dir: Path) -> dict[str, Path]:
    paths = {
        "facts.json": out_dir / "facts.json",
        "report.md": out_dir / "report.md",
        "report.html": out_dir / "report.html",
    }
    paths["facts.json"].write_text(doc.to_json(), encoding="utf-8")
    paths["report.md"].write_text(render_markdown(doc), encoding="utf-8")
    paths["report.html"].write_text(render_html(doc), encoding="utf-8")
    return paths


def _persist(
    store: Store, doc: FactsDoc, old_ir: list[FunctionIR], new_ir: list[FunctionIR]
) -> None:
    try:
        sid = doc.session.id
        facts_sha = store.put_json(doc.to_dict())
        store.session_db(sid).close()
        store.add_artifact(sid, "facts", facts_sha)
        for image, ir_list in (("old", old_ir), ("new", new_ir)):
            payload = [fn.to_dict() for fn in ir_list]
            sha = store.put_json(payload)
            store.add_artifact(sid, f"ir_{image}", sha)
        log.info("session persisted", extra={"session": sid})
    except OSError as exc:
        log.warning("session persistence failed (non-fatal)", extra={"count": 1})
        log.debug(str(exc))


def summarize_terminal(doc: FactsDoc) -> str:
    """One-glance terminal summary (matches README example shape)."""
    s = doc.summary
    matched = sum(s["matches"].values())
    methods = " · ".join(f"{k} {v}" for k, v in s["matches"].items())
    high = [c for c in doc.changes if c.relevance.score == "high"]
    lines = [
        f"Matched {matched}/{s['functions']['old']} ({methods})",
        f"Changed {s['changed']} · Added {s['added']} · Removed {s['removed']} · "
        f"ambiguous {s['ambiguous']}",
    ]
    for change in high[:5]:
        tags = ", ".join(t.tag for t in change.tags)
        hyp = change.hypotheses[0].cwe if change.hypotheses and change.hypotheses[0].cwe else ""
        lines.append(f"HIGH {change.new_name} {tags} {hyp}".rstrip())
    return "\n".join(lines)
