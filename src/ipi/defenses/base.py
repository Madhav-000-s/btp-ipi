"""Uniform defense interface. CaMeL/Progent reproductions and the envelope monitor all implement this,
so any defense drops into the evaluation grid without touching the harness.

INTERFACE OWNER: Infra.
"""
from __future__ import annotations

import abc
from typing import Any

from ipi.types import Decision, DefenseContext, Observation, ProposedCall


class Defense(abc.ABC):
    name: str = "base"

    def reset(self, ctx: DefenseContext) -> None:
        """Called once per episode, before the first LLM call. Do per-episode setup here
        (e.g. envelope extraction from the user query)."""

    @abc.abstractmethod
    def decide(self, ctx: DefenseContext, call: ProposedCall) -> Decision:
        """Gate one proposed tool call. Must be side-effect free on the environment."""

    def update(self, obs: Observation) -> None:
        """Called after each call is resolved. Stateful defenses (e.g. taint tracking) update here."""

    def spec(self) -> dict[str, Any]:
        """White-box description handed to the adaptive attacker (threat model: defense-aware attacker).
        Return policy text, prompt templates, thresholds — whatever a knowledgeable attacker would know.
        Must NOT include per-episode secrets the attacker couldn't know (e.g. the extracted envelope)
        unless the threat model says so."""
        return {"name": self.name}

    # Optional: some defenses (CaMeL-style) change the *pipeline*, not just the gate.
    def wrap_system_prompt(self, system_prompt: str) -> str:
        return system_prompt


class Chain(Defense):
    """Compose defenses: first non-ALLOW decision wins."""

    def __init__(self, defenses: list[Defense]):
        self.defenses = defenses
        self.name = "+".join(d.name for d in defenses)

    def reset(self, ctx):
        for d in self.defenses:
            d.reset(ctx)

    def decide(self, ctx, call):
        for d in self.defenses:
            dec = d.decide(ctx, call)
            if dec.verdict.value != "allow":
                return Decision(dec.verdict, dec.reason, d.name, dec.detail)
        return Decision.allow()

    def update(self, obs):
        for d in self.defenses:
            d.update(obs)

    def spec(self):
        return {"name": self.name, "components": [d.spec() for d in self.defenses]}
