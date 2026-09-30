"""Docker worker tests (ADR-0008) — skipped locally without docker; the CI `worker`
job builds the image and runs these on GitHub runners."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from fw_diff.worker import WORKER_IMAGE, docker_available, ensure_image

pytestmark = pytest.mark.worker

DOCKER = shutil.which("docker")


@pytest.fixture(scope="module")
def worker_image() -> str:
    if not docker_available():
        pytest.skip("docker not available")
    image = WORKER_IMAGE
    if not ensure_image(image):
        repo_root = Path(__file__).parent.parent
        subprocess.run(
            ["docker", "build", "-f", "docker/ghidra-worker.Dockerfile", "-t", image, "."],
            cwd=repo_root,
            check=True,
        )
    return image


@pytest.fixture()
def tiny_binary(tmp_path: Path) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc not available")
    src = tmp_path / "t.c"
    src.write_text('#include <stdio.h>\nint main(void){printf("hi\\n");return 0;}\n')
    exe = tmp_path / "tiny"
    subprocess.run([gcc, "-O0", str(src), "-o", str(exe)], check=True)
    return exe


def test_worker_lift_in_container(worker_image: str, tiny_binary: Path, tmp_path: Path) -> None:
    from fw_diff.models import LiftTarget
    from fw_diff.worker import lift_in_container

    out = lift_in_container(
        LiftTarget(path=str(tiny_binary), arch="x86_64", base=None),
        tmp_path,
        image=worker_image,
        timeout_s=900,
    )
    assert out.functions, "worker must produce lifted functions"
    names = {fn.name for fn in out.functions}
    assert "main" in names or any("main" in fn.symbols for fn in out.functions)


def test_worker_pipeline_end_to_end(worker_image: str, tiny_binary: Path, tmp_path: Path) -> None:
    """Binary diffed against itself through the container path must be clean."""
    from fw_diff.pipeline import PipelineOptions, run_pipeline

    opts = PipelineOptions(
        out_dir=tmp_path / "out", deterministic=True, worker_mode="docker", max_functions=40
    )
    result = run_pipeline(tiny_binary, tiny_binary, opts)
    assert result.facts.summary["changed"] == 0
    assert result.facts.session.config["worker_mode"] == "docker"


def test_worker_sandbox_flags(tmp_path: Path) -> None:
    from fw_diff.worker import _docker_run_args

    args = _docker_run_args(tmp_path, memory="4g", cpus=2.0)
    joined = " ".join(args)
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--memory 4g" in joined
    assert "--cpus 2.0" in joined
