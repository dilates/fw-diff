"""Session store tests (ADR-0005)."""

from __future__ import annotations

import json

import pytest

from fw_diff.store import SessionLock, Store, sha256_bytes


def test_blob_roundtrip_and_dedupe() -> None:
    store = Store()
    data = b"hello fw-diff"
    sha = store.put_blob(data)
    assert sha == sha256_bytes(data)
    assert store.get_blob(sha) == data
    # same content -> same blob address (dedupe)
    assert store.put_blob(data) == sha


def test_get_missing_blob_raises() -> None:
    store = Store()
    with pytest.raises(FileNotFoundError):
        store.get_blob("ff" * 32)


def test_json_blob_roundtrip() -> None:
    store = Store()
    obj = {"b": 2, "a": 1}
    sha = store.put_json(obj)
    assert json.loads(store.get_blob(sha)) == obj


def test_session_artifacts_lifecycle() -> None:
    store = Store()
    sid = "testsession"
    sha = store.put_json({"facts": True})
    store.add_artifact(sid, "facts", sha)
    store.add_artifact(sid, "facts", sha)  # idempotent
    rows = store.get_artifacts(sid, "facts")
    assert rows == [("facts", sha)]
    assert sid in {r["id"] for r in store.list_sessions()}


def test_session_lock_is_exclusive() -> None:
    store = Store()
    paths = store.create_session("locky")
    with SessionLock(paths), pytest.raises(RuntimeError, match="locked"), SessionLock(paths):
        pass


def test_gc_removes_unreferenced_blobs_only() -> None:
    store = Store()
    keep_sha = store.put_blob(b"referenced")
    drop_sha = store.put_blob(b"unreferenced")
    store.create_session("gc1")
    store.add_artifact("gc1", "facts", keep_sha)
    removed = store.gc()
    assert drop_sha not in {b.name for b in store.objects.glob("*/*")}
    assert store.get_blob(keep_sha) == b"referenced"
    _ = removed


def test_remove_session_gcs_blobs() -> None:
    store = Store()
    sha = store.put_json({"x": 1})
    store.add_artifact("doomed", "facts", sha)
    assert store.remove_session("doomed") is True
    assert store.remove_session("doomed") is False
    assert not (store.objects / sha[:2] / sha).exists()


def test_list_sessions_ignores_corrupt_db() -> None:
    store = Store()
    store.create_session("broken")
    (store.sessions / "broken" / "session.db").write_bytes(b"not a database")
    assert store.list_sessions() == []


def test_lift_cache_roundtrip() -> None:
    store = Store()
    payload = {"functions": [{"id": "F0001"}], "ghidra_version": "11.3.2"}
    store.put_lift_cache("a" * 64, "armv7", None, None, payload)
    key = store.lift_cache_key("a" * 64, "armv7", None, None)
    assert store.get_lift_cache(key) == payload


def test_lift_cache_key_distinguishes_params() -> None:
    store = Store()
    k1 = store.lift_cache_key("a" * 64, "armv7", None, None)
    k2 = store.lift_cache_key("a" * 64, "aarch64", None, None)
    k3 = store.lift_cache_key("a" * 64, "armv7", 0x40000000, None)
    k4 = store.lift_cache_key("a" * 64, "armv7", None, 100)
    assert len({k1, k2, k3, k4}) == 4


def test_lift_cache_miss_returns_none() -> None:
    store = Store()
    assert store.get_lift_cache("b" * 64) is None


def test_lift_cache_corrupt_index_is_a_miss() -> None:
    store = Store()
    store.put_lift_cache("c" * 64, "x86", None, None, {"ok": True})
    key = store.lift_cache_key("c" * 64, "x86", None, None)
    conn = store._cache_db()
    conn.execute("UPDATE lift_cache SET blob_sha = 'ff' WHERE key = ?", (key,))
    conn.commit()
    conn.close()
    assert store.get_lift_cache(key) is None
