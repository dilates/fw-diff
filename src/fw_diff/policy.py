"""CI policy engine (getting-started §4, THREAT_MODEL §3.2).

Policies read ONLY deterministic facts — never LLM prose. Exit semantics:
0 = pass, 1 = fail_on rule hit, 2 = config/ingest error (raised upstream).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from .models import FactsDoc


@dataclass
class PolicyDecision:
    failures: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 1 if self.failures else 0


class PolicyError(ValueError):
    pass


_WHERE_RE = re.compile(r"^(security_relevance|match_method|tag)\s*==\s*(\w+)$")


def load_policy(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise PolicyError("policy file must be a YAML mapping")
    for key in data:
        if key not in ("fail_on", "warn_on"):
            raise PolicyError(f"unknown policy section: {key!r}")
    return data


def evaluate_policy(doc: FactsDoc, policy: dict[str, Any]) -> PolicyDecision:
    decision = PolicyDecision()
    for section, target in (("fail_on", decision.failures), ("warn_on", decision.warnings)):
        for rule in policy.get(section, []) or []:
            hits = _rule_hits(doc, rule, section)
            if hits:
                target.append({"rule": rule, "change_ids": hits})
    return decision


def _rule_hits(doc: FactsDoc, rule: Any, section: str) -> list[str]:
    if isinstance(rule, str):
        rule = {"classifier": rule}
    if not isinstance(rule, dict):
        raise PolicyError(f"{section} rule must be a mapping or string: {rule!r}")

    if "classifier" in rule:
        tag = str(rule["classifier"])
        where = rule.get("where")
        hits: list[str] = []
        for change in doc.changes:
            if tag not in {t.tag for t in change.tags}:
                continue
            if where is not None and not _where_matches(
                where, change.relevance.score, change.match_method, [t.tag for t in change.tags]
            ):
                continue
            hits.append(change.id)
        return hits

    if "removed_function" in rule:
        cond = rule["removed_function"] or {}
        if cond.get("reachable_from_input"):
            return [
                str(r["id"])
                for r in doc.removed
                if isinstance(r.get("auth_surface"), bool) and r["auth_surface"]
            ]
        return [str(r["id"]) for r in doc.removed] if cond.get("any") else []

    raise PolicyError(f"{section} rule must have 'classifier' or 'removed_function'")


def _where_matches(expr: str, relevance: str, match_method: str, tags: list[str]) -> bool:
    m = _WHERE_RE.match(expr.strip())
    if not m:
        raise PolicyError(
            f"unsupported 'where' expression: {expr!r} "
            "(supported: security_relevance|match_method|tag == <value>)"
        )
    field, value = m.group(1), m.group(2)
    if field == "security_relevance":
        return relevance == value
    if field == "match_method":
        return match_method == value
    if field == "tag":
        return value in tags
    return False
