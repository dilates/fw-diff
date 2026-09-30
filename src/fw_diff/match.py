"""Multi-stage function matcher (pipeline-spec §4, ADR-0006).

Stages, in order:
  S0 anchors    — symbol-name pins + entry points (confidence 1.0)
  S1 exact hash — identical ``h_exact`` groups
  S2 structural — call-graph-anchored iterative voting over simhash(struct tokens)
  S3 embedding  — optional (needs the ``embed`` extra + a model); ambiguity-guarded
  S4 manual     — ``--map`` overrides, labeled ``manual`` (confidence 1.0)

Deterministic by construction: candidates are generated in sorted order, scoring is a pure
function of the IR, and ties break by (id). Same inputs -> same MatchResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import FunctionIR
from .normalize import NormalizedFunction, normalize_image
from .simhash import simhash64, simhash_similarity

TAU = 0.80  # S2 acceptance threshold (pipeline-spec §4, calibrated vs corpus)
DELTA_MARGIN = 0.08  # S3 ambiguity margin (pipeline-spec §4)
EMBED_SIM_MIN = 0.82
MAX_ROUNDS = 6

W_SIMHASH, W_CALLSIG, W_STRINGS, W_PARAMS = 0.50, 0.25, 0.15, 0.10

STAGE_EXACT = "exact_hash"
STAGE_STRUCT = "struct_hash"
STAGE_ANCHOR = "callgraph_anchor"
STAGE_EMBED = "embedding"
STAGE_MANUAL = "manual"


@dataclass
class MatchPair:
    old_id: str
    new_id: str
    method: str
    confidence: float


@dataclass
class MatchResult:
    pairs: list[MatchPair] = field(default_factory=list)
    ambiguous: list[dict[str, object]] = field(default_factory=list)
    added: list[str] = field(default_factory=list)  # new-image ids without a partner
    removed: list[str] = field(default_factory=list)  # old-image ids without a partner
    skipped_stages: list[str] = field(default_factory=list)

    def method_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for pair in self.pairs:
            counts[pair.method] = counts.get(pair.method, 0) + 1
        return dict(sorted(counts.items()))

    def by_new_id(self) -> dict[str, MatchPair]:
        return {p.new_id: p for p in self.pairs}

    def by_old_id(self) -> dict[str, MatchPair]:
        return {p.old_id: p for p in self.pairs}


class EmbeddingProvider:
    """Interface for S3; concrete providers live behind the ``embed`` extra."""

    name: str = "abstract"

    def embed(self, texts: list[str]) -> list[list[float]]:  # pragma: no cover
        raise NotImplementedError


@dataclass(frozen=True)
class Thresholds:
    tau: float = TAU
    delta_margin: float = DELTA_MARGIN
    embed_sim_min: float = EMBED_SIM_MIN
    max_rounds: int = MAX_ROUNDS

    def to_dict(self) -> dict[str, object]:
        return {
            "tau": self.tau,
            "delta_margin": self.delta_margin,
            "embed_sim_min": self.embed_sim_min,
            "max_rounds": self.max_rounds,
        }


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


class Matcher:
    """S0→S3 matcher over two normalized images."""

    def __init__(
        self,
        old_ir: list[FunctionIR],
        new_ir: list[FunctionIR],
        old_norm: dict[str, NormalizedFunction],
        new_norm: dict[str, NormalizedFunction],
        *,
        embedder: EmbeddingProvider | None = None,
        thresholds: Thresholds | None = None,
    ) -> None:
        self.old_ir = {fn.id: fn for fn in sorted(old_ir, key=lambda f: (f.addr, f.id))}
        self.new_ir = {fn.id: fn for fn in sorted(new_ir, key=lambda f: (f.addr, f.id))}
        self.old_norm = old_norm
        self.new_norm = new_norm
        self.embedder = embedder
        self.thresholds = thresholds or Thresholds()
        self.result = MatchResult()
        self._matched_old: dict[str, str] = {}  # old_id -> new_id
        self._matched_new: dict[str, str] = {}  # new_id -> old_id

    # -- helpers ---------------------------------------------------------------

    def _canonical_calls(self, image: str, fid: str) -> set[str]:
        ir_map = self.old_ir if image == "old" else self.new_ir
        canon: set[str] = set()
        for callee in ir_map[fid].calls_out:
            if image == "new" and callee in self._matched_new:
                canon.add(self._matched_new[callee])  # align via current matches
            else:
                canon.add(callee)
        return canon

    def _score(self, old_id: str, new_id: str) -> float:
        sim = simhash_similarity(
            simhash64(self.old_norm[old_id].struct_tokens),
            simhash64(self.new_norm[new_id].struct_tokens),
        )
        old_calls = self._canonical_calls("old", old_id)
        new_calls = self._canonical_calls("new", new_id)
        callsig = _jaccard(
            {c for c in old_calls if c.startswith("IMPORT_") or c in self.old_ir},
            {c for c in new_calls if c.startswith("IMPORT_") or c in self.old_ir},
        )
        strings = _jaccard(set(self.old_norm[old_id].strings), set(self.new_norm[new_id].strings))
        params = 1.0 if self.old_ir[old_id].params == self.new_ir[new_id].params else 0.0
        return W_SIMHASH * sim + W_CALLSIG * callsig + W_STRINGS * strings + W_PARAMS * params

    def _accept(self, old_id: str, new_id: str, method: str, confidence: float) -> None:
        self._matched_old[old_id] = new_id
        self._matched_new[new_id] = old_id
        self.result.pairs.append(MatchPair(old_id, new_id, method, round(confidence, 4)))

    # -- stages ----------------------------------------------------------------

    def _stage0_anchors(self) -> None:
        old_syms: dict[str, list[str]] = {}
        for fid, fn in self.old_ir.items():
            for sym in fn.symbols:
                if sym:
                    old_syms.setdefault(sym, []).append(fid)
        for new_id, fn in sorted(self.new_ir.items()):
            for sym in fn.symbols:
                unmatched = [c for c in old_syms.get(sym, []) if c not in self._matched_old]
                if len(unmatched) == 1:
                    self._accept(unmatched[0], new_id, STAGE_ANCHOR, 1.0)
                    break
        old_entries = sorted(fid for fid, fn in self.old_ir.items() if fn.entry)
        new_entries = sorted(fid for fid, fn in self.new_ir.items() if fn.entry)
        if (
            len(old_entries) == 1
            and len(new_entries) == 1
            and old_entries[0] not in self._matched_old
            and new_entries[0] not in self._matched_new
        ):
            self._accept(old_entries[0], new_entries[0], STAGE_ANCHOR, 1.0)

    def _stage1b_struct_unique(self) -> None:
        """Unique ``h_struct`` on both sides -> struct_hash match (conf 0.95)."""
        old_groups: dict[str, list[str]] = {}
        for fid, fn in sorted(self.old_ir.items()):
            if fid not in self._matched_old:
                old_groups.setdefault(fn.h_struct, []).append(fid)
        new_groups: dict[str, list[str]] = {}
        for fid, fn in sorted(self.new_ir.items()):
            if fid not in self._matched_new:
                new_groups.setdefault(fn.h_struct, []).append(fid)
        for h, old_ids in sorted(old_groups.items()):
            if len(old_ids) == 1 and len(new_groups.get(h, [])) == 1:
                old_id = old_ids[0]
                new_id = new_groups[h][0]
                if old_id not in self._matched_old and new_id not in self._matched_new:
                    self._accept(old_id, new_id, STAGE_STRUCT, 0.95)

    def _stage1_exact(self) -> None:
        old_groups: dict[str, list[str]] = {}
        for fid, fn in sorted(self.old_ir.items()):
            if fid not in self._matched_old:
                old_groups.setdefault(fn.h_exact, []).append(fid)
        for new_id, fn in sorted(self.new_ir.items()):
            if new_id in self._matched_new:
                continue
            free = [g for g in old_groups.get(fn.h_exact, []) if g not in self._matched_old]
            if free:
                self._accept(free[0], new_id, STAGE_EXACT, 1.0)

    def _candidates_for(self, new_id: str) -> set[str]:
        """Candidate old partners: call-neighborhoods of matched counterparts, shared
        imports, shared strings (pipeline-spec §4 S2)."""
        fn = self.new_ir[new_id]
        candidates: set[str] = set()
        for neighbor in list(fn.calls_out) + list(fn.calls_in):
            if neighbor in self._matched_new:
                ofn = self.old_ir[self._matched_new[neighbor]]
                for cand in list(ofn.calls_out) + list(ofn.calls_in):
                    if cand in self.old_ir and cand not in self._matched_old:
                        candidates.add(cand)
        for imp in fn.imports_called:
            for old_id, ofn in self.old_ir.items():
                if old_id not in self._matched_old and imp in ofn.imports_called:
                    candidates.add(old_id)
        for s in self.new_norm[new_id].strings:
            for old_id, onorm in self.old_norm.items():
                if old_id not in self._matched_old and s in onorm.strings:
                    candidates.add(old_id)
        return candidates

    def _stage2_structural(self) -> None:
        tau = self.thresholds.tau
        for _ in range(self.thresholds.max_rounds):
            best_old: dict[str, tuple[float, str]] = {}
            best_new: dict[str, tuple[float, str]] = {}
            for new_id in sorted(self.new_ir):
                if new_id in self._matched_new:
                    continue
                for old_id in sorted(self._candidates_for(new_id)):
                    score = self._score(old_id, new_id)
                    prev = best_old.get(new_id)
                    if prev is None or score > prev[0]:
                        best_old[new_id] = (score, old_id)
                    prev_b = best_new.get(old_id)
                    if prev_b is None or score > prev_b[0]:
                        best_new[old_id] = (score, new_id)
            accepted = 0
            for new_id in sorted(best_old):
                score, old_id = best_old[new_id]
                mutual = best_new.get(old_id, (None, None))[1] == new_id
                if score >= tau and mutual:
                    if new_id not in self._matched_new and old_id not in self._matched_old:
                        self._accept(old_id, new_id, STAGE_STRUCT, score)
                        accepted += 1
                elif score >= tau:
                    # strong candidate, not mutual-best -> report as ambiguous, never guess
                    self._record_ambiguous(old_id, new_id, score)
            if accepted == 0:
                break

    def _record_ambiguous(self, old_id: str, new_id: str, score: float) -> None:
        for entry in self.result.ambiguous:
            if entry["old"] == old_id and entry["new"] == new_id:
                return
        self.result.ambiguous.append(
            {"old": old_id, "new": new_id, "candidates": [{"sim": round(score, 4)}]}
        )

    def _stage3_embedding(self) -> None:
        if self.embedder is None:
            self.result.skipped_stages.append(STAGE_EMBED)
            return
        old_free = [fid for fid in sorted(self.old_ir) if fid not in self._matched_old]
        new_free = [fid for fid in sorted(self.new_ir) if fid not in self._matched_new]
        if not old_free or not new_free:
            return
        old_vecs = self.embedder.embed([self.old_norm[f].text_struct for f in old_free])
        new_vecs = self.embedder.embed([self.new_norm[f].text_struct for f in new_free])

        def cos(a: list[float], b: list[float]) -> float:
            num = sum(x * y for x, y in zip(a, b, strict=False))
            da = sum(x * x for x in a) ** 0.5
            db = sum(x * x for x in b) ** 0.5
            return num / (da * db) if da and db else 0.0

        for j, new_id in enumerate(new_free):
            sims = sorted(
                ((cos(new_vecs[j], old_vecs[i]), old_id) for i, old_id in enumerate(old_free)),
                key=lambda t: (-t[0], t[1]),
            )
            if not sims:
                continue
            top_sim, top_old = sims[0]
            margin = top_sim - (sims[1][0] if len(sims) > 1 else 0.0)
            if top_sim >= self.thresholds.embed_sim_min and margin >= self.thresholds.delta_margin:
                self._accept(top_old, new_id, STAGE_EMBED, top_sim)
            elif top_sim >= self.thresholds.tau:
                self._record_ambiguous(top_old, new_id, top_sim)

    def _finish(self) -> None:
        self.result.added = sorted(fid for fid in self.new_ir if fid not in self._matched_new)
        self.result.removed = sorted(fid for fid in self.old_ir if fid not in self._matched_old)
        self.result.pairs.sort(key=lambda p: (p.new_id, p.old_id))

    def run(self) -> MatchResult:
        self._stage0_anchors()
        self._stage1_exact()
        self._stage1b_struct_unique()
        self._stage2_structural()
        self._stage3_embedding()
        self._finish()
        return self.result


def run_match(
    old_ir: list[FunctionIR],
    new_ir: list[FunctionIR],
    *,
    embedder: EmbeddingProvider | None = None,
    thresholds: Thresholds | None = None,
) -> tuple[MatchResult, dict[str, NormalizedFunction], dict[str, NormalizedFunction]]:
    """Normalize both images, then match. Returns (result, old_norm, new_norm)."""
    old_norm = normalize_image(old_ir)
    new_norm = normalize_image(new_ir)
    matcher = Matcher(old_ir, new_ir, old_norm, new_norm, embedder=embedder, thresholds=thresholds)
    return matcher.run(), old_norm, new_norm


def apply_manual_map(
    result: MatchResult,
    old_ir: dict[str, FunctionIR],
    new_ir: dict[str, FunctionIR],
    mapping: list[tuple[str, str]],
) -> MatchResult:
    """S4: force pairs from `--map` (old_id, new_id); unmatched entries become matched."""
    for old_id, new_id in sorted(mapping):
        if old_id in old_ir and new_id in new_ir:
            result.pairs.append(MatchPair(old_id, new_id, STAGE_MANUAL, 1.0))
            if new_id in result.added:
                result.added.remove(new_id)
            if old_id in result.removed:
                result.removed.remove(old_id)
    result.pairs.sort(key=lambda p: (p.new_id, p.old_id))
    return result


__all__ = [
    "STAGE_ANCHOR",
    "STAGE_EMBED",
    "STAGE_EXACT",
    "STAGE_MANUAL",
    "STAGE_STRUCT",
    "EmbeddingProvider",
    "MatchPair",
    "MatchResult",
    "Matcher",
    "Thresholds",
    "apply_manual_map",
    "run_match",
]
