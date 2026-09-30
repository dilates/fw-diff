"""Plugin system (docs/design/plugin-api.md — v1 stability starts in v0.3).

Discovery is via Python entrypoint groups; classifier plugins must be pure functions of
the change facts (no I/O, no randomness). Built-in classifiers always run first; plugin
tags are appended and sorted for deterministic output.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from typing import Any, Protocol

from .log import get_logger

log = get_logger("fw_diff.plugins")

GROUPS = (
    "fw_diff.ingestors",
    "fw_diff.classifiers",
    "fw_diff.renderers",
    "fw_diff.llm",
)


@dataclass(frozen=True)
class PluginInfo:
    group: str
    name: str
    value: str


class ClassifierPlugin(Protocol):
    """v1 contract (plugin-api.md): pure, deterministic, evidence-carrying tags."""

    tag: str

    def check(self, change: Any, old_fn: Any, new_fn: Any) -> Any:
        """Return a ``Tag`` (with evidence) or ``None``. Must not mutate inputs."""
        ...


def discover(group: str) -> list[PluginInfo]:
    eps = metadata.entry_points(group=group)
    return [PluginInfo(group=group, name=ep.name, value=ep.value) for ep in eps]


def list_plugins() -> list[PluginInfo]:
    out: list[PluginInfo] = []
    for group in GROUPS:
        out.extend(discover(group))
    return sorted(out, key=lambda p: (p.group, p.name))


def load_classifiers() -> list[ClassifierPlugin]:
    plugins: list[ClassifierPlugin] = []
    for info in discover("fw_diff.classifiers"):
        try:
            cls = metadata.entry_points(group="fw_diff.classifiers")[info.name].load()
            plugins.append(cls())
        except Exception as exc:  # plugin failure must never kill the pipeline
            log.warning(
                "classifier plugin %s failed to load: %s",
                info.name,
                exc,
                extra={"count": 1},
            )
    return sorted(plugins, key=lambda p: getattr(p, "tag", p.__class__.__name__))


def apply_plugin_classifiers(
    change: Any, old_fn: Any, new_fn: Any, classifiers: list[ClassifierPlugin]
) -> None:
    """Run classifier plugins on a change; appended tags are deterministic (sorted)."""
    for plugin in classifiers:
        try:
            tag = plugin.check(change, old_fn, new_fn)
        except Exception as exc:
            log.warning(
                "classifier plugin %s raised: %s",
                getattr(plugin, "tag", plugin),
                exc,
                extra={"count": 1},
            )
            continue
        if tag is None:
            continue
        from .models import Tag as BuiltTag

        if isinstance(tag, BuiltTag) and tag not in change.tags:
            change.tags.append(tag)
            change.tags = sorted(change.tags, key=lambda t: t.tag)
