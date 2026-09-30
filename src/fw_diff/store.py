"""Session store: SQLite + content-addressed blobs (ADR-0005).

Layout (ARCHITECTURE §5):
    ~/.cache/fw-diff/objects/<sha[:2]>/<sha>   blobs (images, IR bundles, facts, reports)
    ~/.cache/fw-diff/sessions/<id>/session.db  per-session SQLite DB

Single-writer per session (flock); workers are stateless and return data, not state.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from .log import get_logger

log = get_logger("fw_diff.store")

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
    kind TEXT NOT NULL,
    blob_sha TEXT NOT NULL,
    created REAL NOT NULL,
    PRIMARY KEY (kind, blob_sha)
);
"""


@dataclass
class SessionPaths:
    root: Path
    db: Path


def default_cache_root() -> Path:
    return Path(os.environ.get("FW_DIFF_CACHE", Path.home() / ".cache" / "fw-diff"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Store:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or default_cache_root()
        self.objects = self.root / "objects"
        self.sessions = self.root / "sessions"

    # -- blobs ---------------------------------------------------------------

    def put_blob(self, data: bytes) -> str:
        sha = sha256_bytes(data)
        blob = self.objects / sha[:2] / sha
        if not blob.exists():
            blob.parent.mkdir(parents=True, exist_ok=True)
            tmp = blob.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, blob)
            log.debug("blob stored", extra={"count": 1})
        return sha

    def get_blob(self, sha: str) -> bytes:
        blob = self.objects / sha[:2] / sha
        if not blob.exists():
            raise FileNotFoundError(f"blob {sha} missing from store")
        return blob.read_bytes()

    def put_json(self, obj: object) -> str:
        return self.put_blob(json.dumps(obj, sort_keys=True, indent=2).encode())

    # -- sessions ------------------------------------------------------------

    def session_paths(self, session_id: str) -> SessionPaths:
        sdir = self.sessions / session_id
        return SessionPaths(root=sdir, db=sdir / "session.db")

    def create_session(self, session_id: str) -> SessionPaths:
        paths = self.session_paths(session_id)
        paths.root.mkdir(parents=True, exist_ok=True)
        return paths

    def session_db(self, session_id: str) -> sqlite3.Connection:
        paths = self.create_session(session_id)
        conn = sqlite3.connect(paths.db)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.executescript(_SCHEMA)
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
        return conn

    def add_artifact(self, session_id: str, kind: str, blob_sha: str) -> None:
        conn = self.session_db(session_id)
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO artifacts (kind, blob_sha, created) VALUES (?, ?, ?)",
                (kind, blob_sha, time.time()),
            )
        conn.close()

    def get_artifacts(self, session_id: str, kind: str | None = None) -> list[tuple[str, str]]:
        conn = self.session_db(session_id)
        if kind is None:
            rows = conn.execute("SELECT kind, blob_sha FROM artifacts").fetchall()
        else:
            rows = conn.execute(
                "SELECT kind, blob_sha FROM artifacts WHERE kind = ?", (kind,)
            ).fetchall()
        conn.close()
        return sorted(rows)

    def list_sessions(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        if not self.sessions.exists():
            return out
        for sdir in sorted(self.sessions.iterdir()):
            db = sdir / "session.db"
            if not db.exists():
                continue
            try:
                conn = sqlite3.connect(db)
                row = conn.execute("SELECT value FROM meta WHERE key = 'created'").fetchone()
                conn.close()
                out.append({"id": sdir.name, "created": row[0] if row else "?"})
            except sqlite3.DatabaseError:
                continue
        return out

    def remove_session(self, session_id: str) -> bool:
        sdir = self.sessions / session_id
        if not sdir.exists():
            return False
        shutil.rmtree(sdir, ignore_errors=True)
        # GC now sees remaining sessions only: this session's blobs vanish unless
        # another session references them (content-addressed sharing, ADR-0005)
        self.gc()
        return True

    def gc(self, keep: set[str] | None = None, older_days: float | None = None) -> int:
        """Remove unreferenced blobs; returns count removed."""
        referenced: set[str] = set(keep or set())
        for db in self.sessions.glob("*/session.db"):
            try:
                conn = sqlite3.connect(db)
                for (sha,) in conn.execute("SELECT blob_sha FROM artifacts"):
                    referenced.add(sha)
                conn.close()
            except sqlite3.DatabaseError:
                continue
        removed = 0
        if not self.objects.exists():
            return 0
        cutoff = time.time() - (older_days * 86400 if older_days else 0)
        for shard in self.objects.iterdir():
            if not shard.is_dir():
                continue
            for blob in shard.iterdir():
                if older_days is not None and blob.stat().st_mtime > cutoff:
                    continue
                if blob.name not in referenced:
                    blob.unlink(missing_ok=True)
                    removed += 1
            if not any(shard.iterdir()):
                shard.rmdir()
        return removed


class SessionLock:
    """Advisory single-writer lock for a session directory."""

    def __init__(self, paths: SessionPaths) -> None:
        self.path = paths.root / "lock"
        self._fh: IO[Any] | None = None

    def __enter__(self) -> SessionLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w")
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._fh.close()
            self._fh = None
            raise RuntimeError(
                "session is locked by another fw-diff process (single-writer, ADR-0005)"
            ) from exc
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fh is not None:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None
