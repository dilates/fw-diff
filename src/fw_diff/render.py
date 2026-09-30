"""Report renderers: facts.json (via models), report.md, report.html (ADR-0010).

The HTML report is single-file, offline, and must contain no external URLs — enforced by a
test (testing-strategy §1) and a release lint rule.
"""

from __future__ import annotations

import html
from typing import Any

from .models import FactsDoc


def render_markdown(doc: FactsDoc) -> str:
    s = doc.session
    old_name = s.old_manifest.path
    new_name = s.new_manifest.path
    lines: list[str] = []
    lines.append(f"# fw-diff: {old_name} → {new_name}")
    when = s.created_utc or "(deterministic session — no wall-clock timestamp)"
    lines.append(f"*Generated {when} · fw-diff {doc.tool_version} · Ghidra {doc.ghidra or 'n/a'}*")
    lines.append("")
    summ = doc.summary
    matched = sum(summ["matches"].values())
    lines.append(
        f"**Matched {matched}/{summ['functions']['old']}** · changed {summ['changed']} · "
        f"added {summ['added']} · removed {summ['removed']} · ambiguous {summ['ambiguous']}"
    )
    if summ.get("skipped_stages"):
        lines.append("")
        lines.append(f"*Stages skipped: {', '.join(summ['skipped_stages'])}*")
    lines.append("")
    lines.append(f"## High-relevance changes ({summ['security_relevance']['high']})")
    lines.append("")
    _changes_md(lines, doc, "high")
    lines.append(f"## Medium-relevance changes ({summ['security_relevance']['medium']})")
    lines.append("")
    _changes_md(lines, doc, "medium")
    lines.append(f"## Low-relevance changes ({summ['security_relevance']['low']})")
    lines.append("")
    _changes_md(lines, doc, "low")
    lines.append("## Added / removed / ambiguous")
    lines.append("")
    lines.append(
        f"- added: {len(doc.added)} · removed: {len(doc.removed)} · ambiguous: {len(doc.ambiguous)}"
    )
    lines.append("")
    lines.append("## Appendix")
    lines.append("")
    lines.append(f"- match methods: {summ['matches']}")
    lines.append(f"- thresholds/config: {s.config}")
    if doc.ghidra is None:
        lines.append("- Ghidra: not used (fixture/demo session)")
    lines.append(f"- old manifest sha256: `{s.old_manifest.sha256[:16]}…`")
    lines.append(f"- new manifest sha256: `{s.new_manifest.sha256[:16]}…`")
    return "\n".join(lines) + "\n"


def _changes_md(lines: list[str], doc: FactsDoc, level: str) -> None:
    wrote = False
    for change in doc.changes:
        if change.relevance.score != level:
            continue
        wrote = True
        tags = ", ".join(t.tag for t in change.tags) or "no-classifier"
        hyp = change.hypotheses[0] if change.hypotheses else None
        hyp_txt = f" · ({hyp.cwe} {hyp.label})" if hyp else ""
        lines.append(f"### [{change.id}] {change.new_name} — {level.upper()} · {tags}{hyp_txt}")
        lines.append("")
        if change.explain is not None:
            lines.append(change.explain.narrative)
            lines.append("")
        for edit in change.edits[:6]:
            if edit.op == "insert" and edit.new_snippet:
                lines.append(f"- `+ {edit.new_snippet}`")
            elif edit.op == "delete" and edit.old_snippet:
                lines.append(f"- `- {edit.old_snippet}`")
            elif edit.op == "update":
                lines.append(f"- `~ {edit.old_snippet}` → `{edit.new_snippet}`")
        if len(change.edits) > 6:
            lines.append(f"- … {len(change.edits) - 6} more edits")
        lines.append("")
    if not wrote:
        lines.append("_none_")
        lines.append("")


_CSS = """
body{font-family:ui-monospace,Menlo,monospace;margin:2rem auto;max-width:64rem;
     color:#1a1a2e;background:#fafafa;line-height:1.5}
h1{font-size:1.4rem;border-bottom:2px solid #16213e;padding-bottom:.4rem}
h2{font-size:1.1rem;margin-top:2rem;color:#16213e}
table{border-collapse:collapse;width:100%;margin:.8rem 0;font-size:.85rem}
th,td{border:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#e8e8ef}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:.6rem;font-size:.75rem;
       color:#fff}
.high{background:#c0392b}.medium{background:#d48806}.low{background:#7f8c8d}
code,pre{background:#eee;padding:.05rem .3rem;border-radius:.25rem}
pre{padding:.6rem;overflow-x:auto}
.meta{color:#555;font-size:.8rem}
.ins{color:#12745a;background:#e7f6f1;display:block;padding:.1rem .4rem}
.del{color:#8f1d1d;background:#fbeaea;display:block;padding:.1rem .4rem}
footer{margin-top:3rem;font-size:.75rem;color:#777;border-top:1px solid #ddd;padding-top:.6rem}
"""


def render_html(doc: FactsDoc) -> str:
    e = html.escape
    s = doc.session
    summ = doc.summary
    matched = sum(summ["matches"].values())

    def badge(level: str) -> str:
        return f'<span class="badge {level}">{level}</span>'

    rows: list[str] = []
    for change in sorted(
        doc.changes,
        key=lambda c: (
            {h: i for i, h in enumerate(("high", "medium", "low"))}[c.relevance.score],
            c.id,
        ),
    ):
        tags = ", ".join(t.tag for t in change.tags) or "—"
        hyp = " ".join(f"{h.cwe}?" for h in change.hypotheses if h.cwe)
        explain_html = ""
        if change.explain is not None:
            prov = change.explain.provenance
            explain_html = (
                f"<p>{e(change.explain.narrative)}</p>"
                f'<p class="meta">model: {e(str(prov.get("model")))} · prompt '
                f"{e(str(prov.get('prompt_version')))} · claims dropped: "
                f"{e(str(prov.get('dropped_claims')))}</p>"
            )
        edits_html = "".join(
            f'<span class="ins">+ {e(ed.new_snippet)}</span>'
            if ed.op == "insert" and ed.new_snippet
            else f'<span class="del">- {e(ed.old_snippet)}</span>'
            if ed.op == "delete" and ed.old_snippet
            else f"<span>~ {e(ed.old_snippet or '')} → {e(ed.new_snippet or '')}</span>"
            for ed in change.edits[:8]
        )
        evidence_rows = "".join(
            f"<tr><td>{e(t.tag)}</td><td>{e(ev.kind)}</td><td><code>{e(ev.detail)}</code></td></tr>"
            for t in change.tags
            for ev in t.evidence
        )
        rows.append(
            f"<tr><td><code>{e(change.id)}</code></td>"
            f"<td><code>{e(change.new_name)}</code></td>"
            f"<td>{badge(change.relevance.score)}</td><td>{e(tags)}</td><td>{e(hyp)}</td></tr>"
            f"<tr><td colspan=5>{explain_html}{edits_html}"
            + (
                f"<table><tr><th>tag</th><th>evidence kind</th><th>detail</th></tr>"
                f"{evidence_rows}</table>"
                if evidence_rows
                else ""
            )
            + "</td></tr>"
        )

    added_rows = "".join(
        f"<tr><td><code>{e(str(a['id']))}</code></td><td>{e(str(a['name']))}</td>"
        f"<td>{e(str(a.get('auth_surface', False)))}</td>"
        f"<td>{e(', '.join(a.get('first_strings', []) or []))}</td></tr>"
        for a in doc.added
    )
    removed_rows = "".join(
        f"<tr><td><code>{e(str(r['id']))}</code></td><td>{e(str(r['name']))}</td>"
        f"<td>{e(str(r.get('auth_surface', False)))}</td>"
        f"<td>{e(', '.join(r.get('called_by', []) or []))}</td></tr>"
        for r in doc.removed
    )
    amb_rows = "".join(
        f"<tr><td><code>{e(str(a['old']))}</code></td><td><code>{e(str(a['new']))}</code></td>"
        f"<td>{e(str(a.get('candidates')))}</td></tr>"
        for a in doc.ambiguous
    )

    provenance = ""
    if any(c.explain for c in doc.changes):
        first_prov: dict[str, Any] = next(c.explain.provenance for c in doc.changes if c.explain)
        provenance = f'<p class="meta">LLM provenance: {e(str(first_prov))}</p>'

    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>fw-diff report</title><style>" + _CSS + "</style></head><body>"
        f"<h1>fw-diff: {e(s.old_manifest.path)} → {e(s.new_manifest.path)}</h1>"
        f'<p class="meta">fw-diff {e(doc.tool_version)} · Ghidra {e(doc.ghidra or "n/a")} · '
        f"session {e(s.id)} · {e(str(s.created_utc or 'deterministic session'))}</p>"
        f"<p><b>Matched {matched}/{summ['functions']['old']}</b> · "
        f"changed {summ['changed']} · added {summ['added']} · removed {summ['removed']} · "
        f"ambiguous {summ['ambiguous']}</p>" + provenance + "<h2>Changes (by relevance)</h2><table>"
        "<tr><th>id</th><th>function</th><th>relevance</th><th>tags</th><th>CWE hyp.</th></tr>"
        + "".join(rows)
        + "</table>"
        + (
            "<h2>Added</h2><table><tr><th>id</th><th>name</th><th>auth surface</th>"
            "<th>strings</th></tr>" + (added_rows or "<tr><td colspan=4>—</td></tr>") + "</table>"
            if doc.added or doc.removed
            else ""
        )
        + (
            "<h2>Removed</h2><table><tr><th>id</th><th>name</th><th>auth surface</th>"
            "<th>called by</th></tr>" + removed_rows + "</table>"
            if doc.removed
            else ""
        )
        + (
            "<h2>Ambiguous (left for human mapping)</h2><table><tr><th>old</th><th>new</th>"
            "<th>candidates</th></tr>" + amb_rows + "</table>"
            if doc.ambiguous
            else ""
        )
        + "<h2>Appendix</h2>"
        f"<pre>{e(str(summ['matches']))}</pre>"
        f"<pre>{e(str(s.config))}</pre>"
        f"<footer>fw-diff {e(doc.tool_version)} — single-file offline report (ADR-0010). "
        "LLM text is annotated output; verify via evidence rows.</footer>"
        "</body></html>"
    )
