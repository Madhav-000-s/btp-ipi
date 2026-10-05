"""Privilege envelope: the set of (tool, sink-constraints, effect) a user request authorizes.

A call is CONTAINED if some capability covers its tool and every pinned sink argument satisfies its
constraint. Anything else is EXPANSION. The envelope is fixed after extraction (monotone: tool output
can never widen it) - this is the narrowing rule.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass, field
from enum import IntEnum
from importlib import resources
from typing import Any

import yaml


class Effect(IntEnum):
    READ = 0
    WRITE_SELF = 1
    WRITE_SHARED = 2
    EXTERNAL_COMM = 3
    FINANCIAL = 4
    ACCOUNT_ADMIN = 5
    DESTRUCTIVE = 6


@dataclass(frozen=True)
class ToolInfo:
    effect: Effect
    sinks: tuple[str, ...] = ()
    payload: tuple[str, ...] = ()


@functools.cache
def taxonomy(suite: str) -> dict[str, ToolInfo]:
    raw = yaml.safe_load(resources.files("ipi.defenses.envelope").joinpath("taxonomy.yaml").read_text())
    out = {}
    for tool, d in (raw.get(suite) or {}).items():
        out[tool] = ToolInfo(Effect[d["effect"].upper()], tuple(d.get("sinks", [])), tuple(d.get("payload", [])))
    return out


def _norm(v: Any) -> str:
    return str(v).strip().lower()


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


@dataclass
class Constraint:
    """Constraint on one sink argument.

    kind:
      any       - extractor could not pin it (value is discovered at runtime, e.g. "reply to the sender").
                  Checker falls back to the provenance signal for these.
      one_of    - every element of the arg value must be in `values` (case-insensitive)
      max       - numeric arg must be <= values[0]  (e.g. amount)
    """
    kind: str = "any"
    values: list[Any] = field(default_factory=list)

    def check(self, value: Any) -> tuple[bool, str]:
        if self.kind == "any":
            return True, "unpinned"
        if self.kind == "one_of":
            allowed = {_norm(x) for x in self.values}
            bad = [x for x in _as_list(value) if _norm(x) not in allowed]
            return (not bad), (f"{bad} not in {sorted(allowed)}" if bad else "pinned-match")
        if self.kind == "max":
            try:
                ok = float(value) <= float(self.values[0])
            except (TypeError, ValueError):
                return False, f"non-numeric {value!r}"
            return ok, ("within-max" if ok else f"{value} > {self.values[0]}")
        return False, f"unknown constraint kind {self.kind}"


@dataclass
class Capability:
    tool: str
    constraints: dict[str, Constraint] = field(default_factory=dict)
    max_uses: int | None = None  # None = unlimited
    rationale: str = ""          # extractor's justification, logged for analysis
    uses: int = 0


@dataclass
class Envelope:
    capabilities: list[Capability] = field(default_factory=list)
    allow_reads: bool = True   # unlisted READ tools without sinks are in-envelope (reading is not expansion)

    def to_dict(self) -> dict:
        return {
            "allow_reads": self.allow_reads,
            "capabilities": [
                {"tool": c.tool, "max_uses": c.max_uses, "rationale": c.rationale,
                 "constraints": {k: {"kind": v.kind, "values": v.values} for k, v in c.constraints.items()}}
                for c in self.capabilities
            ],
        }

    @staticmethod
    def from_dict(d: dict) -> "Envelope":
        caps = []
        for c in d.get("capabilities", []):
            cons = {k: Constraint(v.get("kind", "any"), list(v.get("values", []))) for k, v in (c.get("constraints") or {}).items()}
            caps.append(Capability(c["tool"], cons, c.get("max_uses"), c.get("rationale", "")))
        return Envelope(caps, d.get("allow_reads", True))

    def tools(self) -> set[str]:
        return {c.tool for c in self.capabilities}
