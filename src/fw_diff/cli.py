"""fw-diff CLI (typer). Exit codes: 0 ok · 1 policy fail · 2 usage/ingest error."""

from __future__ import annotations

import json
from importlib import metadata
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .demo import load_demo_ir
from .doctor import is_healthy, run_checks
from .explain import ExplainConfig
from .ingest import IngestError, ResourceCaps, ingest
from .log import setup_logging
from .models import ImageManifest
from .pipeline import PipelineError, PipelineOptions, run_from_ir, run_pipeline, summarize_terminal
from .policy import PolicyError, load_policy
from .store import Store

app = typer.Typer(
    name="fw-diff",
    help="Explain what changed between two firmware images — in plain English.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True, style="red")

LlmOpt = Annotated[str, typer.Option("--llm", help="off | ollama | openai-compat")]
LlmModelOpt = Annotated[str, typer.Option("--llm-model", help="model id for the provider")]
LlmUrlOpt = Annotated[str | None, typer.Option("--llm-url", help="OpenAI-compatible base URL")]
ArchOpt = Annotated[str | None, typer.Option("--arch", help="arch override (armv7, aarch64, …)")]
BaseOpt = Annotated[int | None, typer.Option("--base", help="base address for raw binaries")]
OutOpt = Annotated[Path, typer.Option("--out", help="output directory")]
DetOpt = Annotated[
    bool, typer.Option("--deterministic", help="derive session id from content; no timestamps")
]
WorkerOpt = Annotated[str, typer.Option("--worker-mode", help="local (v0.1) | docker (v0.2)")]
MapOpt = Annotated[Path | None, typer.Option("--map", help="TSV: old_id, new_id[, reason]")]


def _opts(
    arch: str | None,
    base: int | None,
    out: Path,
    llm: str,
    llm_model: str,
    llm_url: str | None,
    deterministic: bool,
    worker_mode: str,
    map_file: Path | None,
    max_functions: int | None,
    jvm_heap: str | None,
) -> PipelineOptions:
    map_pairs: list[tuple[str, str]] = []
    if map_file is not None:
        for line in map_file.read_text().splitlines():
            parts = [p for p in line.split("\t") if p][:2]
            if len(parts) == 2:
                map_pairs.append((parts[0], parts[1]))
    provider = llm.lower()
    if provider not in ("off", "ollama", "openai-compat"):
        raise typer.BadParameter("--llm must be off | ollama | openai-compat")
    return PipelineOptions(
        arch=arch,
        base=base,
        out_dir=out,
        llm=ExplainConfig(provider=provider, url=llm_url, model=llm_model),
        deterministic=deterministic,
        max_functions=max_functions,
        jvm_heap=jvm_heap,
        worker_mode=worker_mode,
        map_pairs=map_pairs,
    )


def _load_policy(policy: Path | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    try:
        return load_policy(str(policy))
    except PolicyError as exc:
        err_console.print(f"policy error: {exc}")
        raise typer.Exit(2) from exc


@app.command()
def explain(
    old: Annotated[Path, typer.Argument()],
    new: Annotated[Path, typer.Argument()],
    arch: ArchOpt = None,
    base: BaseOpt = None,
    out: OutOpt = Path("out"),
    llm: LlmOpt = "ollama",
    llm_model: LlmModelOpt = "llama3.1:8b",
    llm_url: LlmUrlOpt = None,
    worker_mode: WorkerOpt = "local",
    map_file: MapOpt = None,
    deterministic: DetOpt = False,
    max_functions: Annotated[int | None, typer.Option("--max-functions")] = None,
    jvm_heap: Annotated[str | None, typer.Option("--jvm-heap")] = None,
) -> None:
    """Full session: diff two images and produce facts + reports (LLM annotation on)."""
    opts = _opts(
        arch,
        base,
        out,
        llm,
        llm_model,
        llm_url,
        deterministic,
        worker_mode,
        map_file,
        max_functions,
        jvm_heap,
    )
    try:
        result = run_pipeline(old, new, opts)
    except (IngestError, PipelineError) as exc:
        err_console.print(f"error: {exc}")
        raise typer.Exit(2) from exc
    console.print(summarize_terminal(result.facts))
    for name, path in result.artifacts.items():
        console.print(f"  [green]wrote[/green] {name} -> {path}")


@app.command()
def ci(
    old: Annotated[Path, typer.Argument()],
    new: Annotated[Path, typer.Argument()],
    policy: Annotated[Path, typer.Option("--policy")],
    arch: ArchOpt = None,
    base: BaseOpt = None,
    out: OutOpt = Path("out"),
    worker_mode: Annotated[
        str, typer.Option("--worker-mode", help="auto (default) | local | docker")
    ] = "auto",
    map_file: MapOpt = None,
    deterministic: DetOpt = True,
) -> None:
    """CI gate: deterministic diff + policy evaluation. LLM is always off here."""
    policy_data = _load_policy(policy)
    opts = _opts(
        arch, base, out, "off", "off", None, deterministic, worker_mode, map_file, None, None
    )
    try:
        result = run_pipeline(old, new, opts, policy=policy_data, caps_hard=True)
    except (IngestError, PipelineError) as exc:
        err_console.print(f"error: {exc}")
        raise typer.Exit(2) from exc
    assert result.policy is not None
    console.print(
        json.dumps(
            {
                "failures": result.policy.failures,
                "warnings": result.policy.warnings,
            },
            indent=2,
            sort_keys=True,
        )
    )
    raise typer.Exit(result.policy.exit_code)


@app.command()
def demo(
    out: OutOpt = Path("out"),
    llm: LlmOpt = "off",
    llm_model: LlmModelOpt = "llama3.1:8b",
    llm_url: LlmUrlOpt = None,
    deterministic: DetOpt = False,
) -> None:
    """End-to-end run on bundled fixture IR — no Ghidra or binaries needed."""
    old_ir, new_ir = load_demo_ir()
    opts = _opts(None, None, out, llm, llm_model, llm_url, deterministic, "local", None, None, None)
    old_manifest = ImageManifest(path="demo/fw-1.4.2.bin", sha256="demo-old")
    new_manifest = ImageManifest(path="demo/fw-1.4.3.bin", sha256="demo-new")
    result = run_from_ir(
        old_ir,
        new_ir,
        opts,
        old_manifest=old_manifest,
        new_manifest=new_manifest,
        ghidra_version=None,
    )
    console.print(summarize_terminal(result.facts))
    for name, path in result.artifacts.items():
        console.print(f"  [green]wrote[/green] {name} -> {path}")


@app.command()
def lift(
    old: Annotated[Path, typer.Argument()],
    new: Annotated[Path, typer.Argument()],
    arch: ArchOpt = None,
    base: BaseOpt = None,
    out: OutOpt = Path("out"),
    max_functions: Annotated[int | None, typer.Option("--max-functions")] = None,
    jvm_heap: Annotated[str | None, typer.Option("--jvm-heap")] = None,
    deterministic: DetOpt = False,
) -> None:
    """Stage only: ingest + lift both images to IR bundles (no matching)."""
    import tempfile

    from .facts import assign_ids
    from .ghidra_lift import lift_image, resolve_calls

    try:
        with tempfile.TemporaryDirectory(prefix="fw-diff-lift-") as tmp:
            caps = ResourceCaps()
            old_manifest = ingest(old, Path(tmp) / "old", caps, arch=arch, base=base)
            new_manifest = ingest(new, Path(tmp) / "new", caps, arch=arch, base=base)
            from .ingest import choose_pair_targets

            old_target, new_target = choose_pair_targets(old_manifest, new_manifest)
            old_out = lift_image(
                old_target.path,
                arch=old_target.arch,
                base=old_target.base,
                workdir=tmp,
                max_functions=max_functions,
                jvm_heap=jvm_heap,
            )
            new_out = lift_image(
                new_target.path,
                arch=new_target.arch,
                base=new_target.base,
                workdir=tmp,
                max_functions=max_functions,
                jvm_heap=jvm_heap,
            )
    except (IngestError, PipelineError) as exc:
        err_console.print(f"error: {exc}")
        raise typer.Exit(2) from exc
    assign_ids(old_out.functions)
    assign_ids(new_out.functions, offset=len(old_out.functions))
    resolve_calls(old_out.functions)
    resolve_calls(new_out.functions)
    out.mkdir(parents=True, exist_ok=True)
    (out / "old_ir.json").write_text(
        json.dumps([fn.to_dict() for fn in old_out.functions], indent=2, sort_keys=True)
    )
    (out / "new_ir.json").write_text(
        json.dumps([fn.to_dict() for fn in new_out.functions], indent=2, sort_keys=True)
    )
    console.print(
        f"[green]lifted[/green] old={len(old_out.functions)} "
        f"new={len(new_out.functions)} functions -> {out}/"
    )


@app.command()
def doctor() -> None:
    """Verify the environment (Ghidra, pyghidra, Java, disk, optional LLM/docker)."""
    table = Table(title="fw-diff doctor")
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")
    checks = run_checks()
    for check in checks:
        table.add_row(
            check.name,
            "[green]ok[/green]"
            if check.ok
            else ("[yellow]advisory[/yellow]" if not check.fatal else "[red]fail[/red]"),
            check.detail,
        )
    console.print(table)
    if not is_healthy(checks):
        raise typer.Exit(2)


sessions_app = typer.Typer(help="Session store operations", no_args_is_help=True)
app.add_typer(sessions_app, name="sessions")


@sessions_app.command("list")
def sessions_list() -> None:
    store = Store()
    rows = store.list_sessions()
    if not rows:
        console.print("no sessions")
        return
    table = Table()
    table.add_column("id")
    table.add_column("created")
    for row in rows:
        table.add_row(row["id"], row["created"])
    console.print(table)


@sessions_app.command("show")
def sessions_show(session_id: Annotated[str, typer.Argument()]) -> None:
    store = Store()
    artifacts = store.get_artifacts(session_id)
    if not artifacts:
        err_console.print(f"session {session_id} not found or empty")
        raise typer.Exit(2)
    for kind, sha in artifacts:
        console.print(f"{kind:10s} {sha}")


@sessions_app.command("rm")
def sessions_rm(session_id: Annotated[str, typer.Argument()]) -> None:
    if Store().remove_session(session_id):
        console.print(f"removed {session_id}")
    else:
        err_console.print(f"session {session_id} not found")
        raise typer.Exit(2)


cache_app = typer.Typer(help="Cache operations", no_args_is_help=True)
app.add_typer(cache_app, name="cache")


@cache_app.command("gc")
def cache_gc(
    older_than_days: Annotated[float | None, typer.Option("--older-than")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    store = Store()
    if dry_run:
        blobs = sum(1 for _ in store.objects.glob("*/*")) if store.objects.exists() else 0
        console.print(f"{blobs} blobs in store (gc not run)")
        return
    removed = store.gc(older_days=older_than_days)
    console.print(f"removed {removed} unreferenced blobs")


plugins_app = typer.Typer(help="Plugin discovery", no_args_is_help=True)
app.add_typer(plugins_app, name="plugins")


@plugins_app.command("list")
def plugins_list() -> None:
    found = 0
    for group in ("fw_diff.ingestors", "fw_diff.classifiers", "fw_diff.renderers", "fw_diff.llm"):
        eps = metadata.entry_points(group=group)
        for ep in eps:
            found += 1
            console.print(f"{group:22s} {ep.name:20s} -> {ep.value}")
    if not found:
        console.print("no plugins installed (docs/design/plugin-api.md)")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"fw-diff {__version__}")
        raise typer.Exit(0)


@app.callback()
def _main(
    version: Annotated[
        bool | None, typer.Option("--version", callback=_version_callback, is_eager=True)
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "INFO",
    log_format: Annotated[str, typer.Option("--log-format")] = "json",
) -> None:
    """fw-diff — deterministic firmware diff with local-LLM explanations."""
    import os

    os.environ["FW_DIFF_LOG_FORMAT"] = log_format
    setup_logging(log_level)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
