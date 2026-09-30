# Plugin API (draft v0)

| | |
|---|---|
| **Status** | Draft — stability commitment begins at v0.3 (ROADMAP) |
| **Owner** | Engineering |

fw-diff is extended through Python entrypoint groups (setuptools `entry_points`, discovered by
`importlib.metadata`). No monkey-patching, no private imports; anything not documented here is
unstable.

## Entry point groups

| Group | Interface | Invoked |
|---|---|---|
| `fw_diff.ingestors` | `Ingestor` | during ingest, by claimed magic/format |
| `fw_diff.classifiers` | `Classifier` | after edit clustering |
| `fw_diff.renderers` | `Renderer` | after facts are finalized |
| `fw_diff.llm` | `LlmProvider` | when `--llm <provider>` matches name |

## Interfaces

```python
from dataclasses import dataclass
from typing import Iterator, Protocol

@dataclass(frozen=True)
class LiftTarget:
    path: str; arch: str; base: int | None

class Ingestor(Protocol):
    name: str                      # unique, lowercase
    def claims(self, head: bytes, name: str) -> bool: ...
    def targets(self, image: "Image", caps: "ResourceCaps") -> Iterator[LiftTarget]: ...
        # must honor caps; must not follow symlinks outside the extract root

class Classifier(Protocol):
    tag: str                       # unique tag emitted into facts
    def check(self, change: "Change", ctx: "ChangeContext") -> "Tag | None": ...
        # pure function of the change + facts; no I/O; returns tag with evidence

class Renderer(Protocol):
    name: str
    def render(self, facts: "FactsDoc", out_dir: "Path") -> "Path": ...

class LlmProvider(Protocol):
    name: str
    def complete(self, request: "ExplainRequest") -> "ExplainResponse": ...
        # must honor request.token_budget; must be deterministic given seed when supported
```

## Rules for plugin authors

1. **Classifiers are pure and deterministic.** Same facts in → same tag out. Non-determinism
   is a release-blocking bug.
2. **Evidence or it didn't happen.** Every returned tag must include evidence rows; the report
   renders your tag with your evidence, so make it human-readable.
3. **Never touch the network.** Ingestors and classifiers run inside the untrusted-input
   boundary; only `LlmProvider` may perform network I/O, and only to its configured endpoint.
4. **Fail loudly, narrow failure.** Raise a typed `PluginError`; fw-diff records the failure in
   the session, renders it in the report appendix, and continues other plugins.
5. Naming: tags use `snake_case`; ingestor names must not shadow built-ins.

## Packaging

Declare entry points in `pyproject.toml`:

```toml
[project.entry-points."fw_diff.classifiers"]
my_corp_crypto = "mycorp.fwdiff:CryptoClassifier"
```

Users enable with `fw-diff plugins list|enable|disable` (v0.3). Disabled plugins are skipped
entirely — their tags vanish from facts (schema stays additive-compatible).

## Versioning of this API

- v0 (now): anything may change; shipped for early plugin writers, marked clearly.
- v1 (v0.3): the four interfaces above + error contract + tag namespace rules are frozen for
  12 months per the v1.0 stability policy (ROADMAP).
