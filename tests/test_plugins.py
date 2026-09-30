"""Plugin API v1 tests: discovery, isolation, deterministic tag merging."""

from __future__ import annotations

from fw_diff.models import Change, Evidence, FunctionIR, Relevance, Tag
from fw_diff.plugins import PluginInfo, apply_plugin_classifiers, list_plugins


class _GoodClassifier:
    tag = "my_plugin_tag"

    def check(self, change, old_fn, new_fn):
        return Tag("my_plugin_tag", 0.5, [Evidence("constant", "plugin evidence")])


class _BadClassifier:
    tag = "boom"

    def check(self, change, old_fn, new_fn):
        raise RuntimeError("plugin bug")


class _ReturningNone:
    tag = "silent"

    def check(self, change, old_fn, new_fn):
        return None


def _change() -> Change:
    return Change(
        id="CH0001",
        old_id="F0001",
        new_id="F0002",
        old_name="a",
        new_name="b",
        match_method="exact_hash",
        match_confidence=1.0,
        relevance=Relevance("low", {}),
    )


def _fns():
    old = FunctionIR(id="F0001", image="old", name="FUN_1", addr=0x1)
    new = FunctionIR(id="F0002", image="new", name="FUN_2", addr=0x2)
    return old, new


def test_good_plugin_tag_appended_and_sorted() -> None:
    change = _change()
    old, new = _fns()
    apply_plugin_classifiers(change, old, new, [_GoodClassifier()])
    assert [t.tag for t in change.tags] == ["my_plugin_tag"]
    assert change.tags[0].evidence[0].detail == "plugin evidence"


def test_plugin_exception_isolated() -> None:
    change = _change()
    old, new = _fns()
    apply_plugin_classifiers(change, old, new, [_BadClassifier(), _GoodClassifier()])
    assert [t.tag for t in change.tags] == ["my_plugin_tag"]  # bad plugin skipped


def test_none_plugin_adds_nothing() -> None:
    change = _change()
    old, new = _fns()
    apply_plugin_classifiers(change, old, new, [_ReturningNone()])
    assert change.tags == []


def test_duplicate_tag_not_duplicated() -> None:
    change = _change()
    old, new = _fns()
    apply_plugin_classifiers(change, old, new, [_GoodClassifier(), _GoodClassifier()])
    assert len(change.tags) == 1


def test_list_plugins_discovery_empty_ok() -> None:
    plugins = list_plugins()
    assert isinstance(plugins, list)
    assert all(isinstance(p, PluginInfo) for p in plugins)


def test_deterministic_merge_order() -> None:
    class TagZ:
        tag = "zzz_plugin"

        def check(self, change, old_fn, new_fn):
            return Tag("zzz_plugin", 0.4, [Evidence("constant", "z")])

    class TagA:
        tag = "aaa_plugin"

        def check(self, change, old_fn, new_fn):
            return Tag("aaa_plugin", 0.4, [Evidence("constant", "a")])

    change = _change()
    old, new = _fns()
    apply_plugin_classifiers(change, old, new, [TagZ(), TagA()])
    assert [t.tag for t in change.tags] == ["aaa_plugin", "zzz_plugin"]
