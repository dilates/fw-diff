"""Structured logging for fw-diff.

JSON logs to stderr by default (machine-readable); ``--log-level`` and
``FW_DIFF_LOG_FORMAT=text`` switch to human-readable output. Stage timings are
emitted at INFO with a ``stage`` field so CI can parse durations.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

_CONFIGURED = False


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        for key in ("stage", "session", "duration_s", "count"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True)


def setup_logging(level: str = "INFO", *, force: bool = False) -> None:
    """Configure root logging once; safe to call repeatedly."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    fmt = os.environ.get("FW_DIFF_LOG_FORMAT", "json")
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "text":
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    else:
        handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    _CONFIGURED = True


def get_logger(name: str = "fw_diff") -> logging.Logger:
    return logging.getLogger(name)


@contextmanager
def stage(log: logging.Logger, name: str, **fields: object) -> Iterator[None]:
    """Log stage start/end with duration; used for the perf budget counters."""
    log.info("stage start", extra={"stage": name, **fields})
    start = time.monotonic()
    try:
        yield
    finally:
        log.info(
            "stage done",
            extra={"stage": name, "duration_s": round(time.monotonic() - start, 2), **fields},
        )
