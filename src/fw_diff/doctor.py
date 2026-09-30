"""Environment doctor (runbook §1): verifies Ghidra, pyghidra, Java, disk, LLM, docker."""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .explain import DEFAULT_OLLAMA_URL


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fatal: bool = False  # False = advisory (e.g. optional LLM/docker)


def _find_ghidra() -> str | None:
    env = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if env and Path(env).is_dir():
        return env
    for pattern in ("/opt/ghidra*", str(Path.home() / "re" / "ghidra_*")):
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[0]
    return None


def _pyghidra_ok() -> tuple[bool, str]:
    try:
        import pyghidra  # noqa: F401

        return True, "pyghidra present"
    except ImportError:
        return False, "pyghidra not installed — pip install 'fw-diff[ghidra]'"


def _java_version() -> tuple[bool, str]:
    java = shutil.which("java")
    if not java:
        return False, "java not on PATH (Ghidra 11.3+ needs Java 21)"
    try:
        out = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=10).stderr
    except subprocess.SubprocessError:
        return False, "java -version failed"
    first = out.splitlines()[0] if out else "?"
    return True, first.strip()


def _ollama() -> tuple[bool, str]:
    base = DEFAULT_OLLAMA_URL.removesuffix("/v1")
    for path in ("/v1/models", "/api/tags"):
        try:
            with urllib.request.urlopen(f"{base}{path}", timeout=2) as resp:
                body = resp.read().decode()[:120]
            return True, f"reachable ({body[:60]}…)" if len(body) > 60 else f"reachable ({body})"
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
    return False, f"not reachable at {DEFAULT_OLLAMA_URL} (optional; --llm off works)"


def run_checks() -> list[Check]:
    checks: list[Check] = []
    checks.append(Check("python >= 3.11", True, f"{sys.version.split()[0]}", fatal=True))

    ghidra = _find_ghidra()
    checks.append(
        Check(
            "ghidra install",
            ghidra is not None,
            ghidra or "not found — set GHIDRA_INSTALL_DIR (docs/runbooks/ops-runbook.md §1)",
            fatal=True,
        )
    )
    ok, detail = _pyghidra_ok()
    checks.append(Check("pyghidra", ok, detail, fatal=True))
    ok, detail = _java_version()
    checks.append(Check("java", ok, detail, fatal=True))
    free = shutil.disk_usage(Path.home()).free // (2**30)
    checks.append(Check("disk free", free >= 5, f"{free} GB free at home"))
    ok, detail = _ollama()
    checks.append(Check("ollama (optional)", ok, detail))
    docker = shutil.which("docker")
    checks.append(
        Check(
            "docker (optional, v0.2 workers)",
            docker is not None,
            docker or "not installed — container worker mode unavailable",
        )
    )
    return checks


def is_healthy(checks: list[Check]) -> bool:
    return all(c.ok for c in checks if c.fatal)
