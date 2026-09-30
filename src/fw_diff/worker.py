"""Docker worker mode (ADR-0008, ROADMAP v0.2).

Lifting untrusted images happens inside a container with no network, read-only rootfs,
and resource caps — results cross the boundary as data (IR bundles on mounted volumes).
Requires the ``fw-diff-worker`` image: build with

    docker build -f docker/ghidra-worker.Dockerfile -t fw-diff-worker:11.3.2 .
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .ghidra_lift import LiftOutput, lift_image, resolve_calls
from .log import get_logger
from .models import FunctionIR, LiftTarget

log = get_logger("fw_diff.worker")

WORKER_IMAGE = "fw-diff-worker:11.3.2"


class WorkerError(RuntimeError):
    pass


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _docker_run_args(workdir: Path, memory: str, cpus: float) -> list[str]:
    """Sandbox flags per ADR-0008: no network, read-only rootfs, caps, tmpfs scratch."""
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--memory",
        memory,
        "--cpus",
        str(cpus),
        "--pids-limit",
        "256",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,size=1g",
        "-v",
        f"{workdir}:/io",
    ]


def lift_in_container(
    target: LiftTarget,
    workdir: Path,
    *,
    image: str = WORKER_IMAGE,
    memory: str = "8g",
    cpus: float = 4.0,
    max_functions: int | None = None,
    timeout_s: int = 3600,
) -> LiftOutput:
    """Lift one target inside the sandboxed worker container; returns parsed IR."""
    workdir = Path(workdir)
    io_dir = workdir / "worker_io"
    io_dir.mkdir(parents=True, exist_ok=True)
    # copy the input in (the mounted dir is writable; the container rootfs is not)
    import hashlib

    in_path = io_dir / f"input_{hashlib.sha256(target.path.encode()).hexdigest()[:12]}"
    shutil.copyfile(target.path, in_path)
    out_path = io_dir / f"{in_path.name}.ir.json"

    # ENTRYPOINT is `python3 -m fw_diff.worker` (Dockerfile): pass args only
    cmd = [
        *_docker_run_args(workdir, memory, cpus),
        image,
        "--input",
        f"/io/{in_path.name}",
        "--arch",
        target.arch,
        "--out",
        f"/io/{out_path.name}",
    ]
    if target.base is not None:
        cmd += ["--base", str(target.base)]
    if max_functions is not None:
        cmd += ["--max-functions", str(max_functions)]

    log.info("worker lift start", extra={"stage": "lift", "count": 1})
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired as exc:
        raise WorkerError(f"worker lift timed out after {timeout_s}s") from exc
    if proc.returncode != 0:
        raise WorkerError(
            f"worker lift failed (exit {proc.returncode}): "
            f"{proc.stderr.strip()[-2000:] or proc.stdout.strip()[-2000:]}"
        )
    if not out_path.exists():
        raise WorkerError("worker produced no IR bundle")
    bundle = json.loads(out_path.read_text())
    functions = [FunctionIR.from_dict(d) for d in bundle["functions"]]
    resolve_calls(functions)
    out = LiftOutput(
        functions=functions,
        ghidra_version=bundle.get("ghidra_version"),
        skipped_functions=int(bundle.get("skipped_functions", 0)),
        lift_gaps=list(bundle.get("lift_gaps", [])),
    )
    for fn in out.functions:
        fn.image = "old"  # caller (pipeline._lift_both) re-tags per side
    return out


def ensure_image(image: str = WORKER_IMAGE) -> bool:
    """True if the worker image exists locally; builds nothing (explicit build step)."""
    if not docker_available():
        return False
    proc = subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False)
    return proc.returncode == 0


# --- container-side entrypoint (python -m fw_diff.worker) ----------------------


def _worker_main(argv: list[str] | None = None) -> int:
    """Runs INSIDE the worker container: lift one image, write an IR bundle.

    Separated from lift_in_container so the host-side code never executes in the
    container and vice versa.
    """
    import argparse
    import json
    import tempfile

    parser = argparse.ArgumentParser(prog="fw-diff-worker")
    parser.add_argument("--input", required=True, help="image path inside the container")
    parser.add_argument("--arch", default=None)
    parser.add_argument("--base", type=lambda x: int(x, 0), default=None)
    parser.add_argument("--out", required=True, help="IR bundle output path")
    parser.add_argument("--max-functions", type=int, default=None)
    parser.add_argument("--jvm-heap", default=None)
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="worker-") as tmp:
        out = lift_image(
            args.input,
            arch=args.arch,
            base=args.base,
            workdir=tmp,
            max_functions=args.max_functions,
            jvm_heap=args.jvm_heap,
        )
    bundle = {
        "functions": [fn.to_dict() for fn in out.functions],
        "ghidra_version": out.ghidra_version,
        "skipped_functions": out.skipped_functions,
        "lift_gaps": out.lift_gaps,
    }
    Path(args.out).write_text(json.dumps(bundle, sort_keys=True, indent=2))
    log.info("worker lift done", extra={"stage": "lift", "count": len(out.functions)})
    return 0


if __name__ == "__main__":
    raise SystemExit(_worker_main())
