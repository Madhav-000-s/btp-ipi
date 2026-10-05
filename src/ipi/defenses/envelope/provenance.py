"""Provenance tagger: for each argument value, where could it have come from?

Provenance is a SIGNAL here, not the gate. The checker consults it only for sink args the envelope
left unpinned (Constraint.kind == "any").

Labels:
  user          - value appears in the user's query
  tool:<name>   - value appears in the output of tool <name> (untrusted: may be attacker-controlled)
  model         - appears nowhere: the model generated it
A value can match several sources; we return all, user first.

Known limitation (say this in the thesis): substring matching is a heuristic. It misses transformed values
(paraphrase, re-formatting) and over-matches short strings. The ANALYSIS workstream should measure its
precision on logged trajectories.
"""
from __future__ import annotations

from typing import Any

MIN_LEN = 4  # shorter values are too ambiguous to trace


def _leaves(v: Any) -> list[str]:
    if isinstance(v, dict):
        return [x for vv in v.values() for x in _leaves(vv)]
    if isinstance(v, (list, tuple, set)):
        return [x for vv in v for x in _leaves(vv)]
    return [] if v is None else [str(v)]


def sources_of(value: Any, user_query: str, tool_outputs: list[tuple[str, str]]) -> dict[str, list[str]]:
    """Map each leaf string of `value` to its candidate sources."""
    q = user_query.lower()
    out: dict[str, list[str]] = {}
    for leaf in _leaves(value):
        s = leaf.strip().lower()
        srcs = []
        if len(s) < MIN_LEN:
            srcs.append("short")
        else:
            if s in q:
                srcs.append("user")
            for tool, text in tool_outputs:
                if s in text.lower():
                    srcs.append(f"tool:{tool}")
            if not srcs:
                srcs.append("model")
        out[leaf] = sorted(set(srcs), key=lambda x: (x != "user", x))
    return out


def untrusted_only(srcs: dict[str, list[str]]) -> list[str]:
    """Leaves whose ONLY sources are tool outputs (no user support)."""
    return [leaf for leaf, s in srcs.items() if "user" not in s and any(x.startswith("tool:") for x in s)]
