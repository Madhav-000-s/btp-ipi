"""Core shared types. Every defense, attack and metric speaks in these.

INTERFACE OWNER: Infra. Changes here need a PR reviewed by all four workstreams.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"  # would ask the user; benchmark resolves via EscalationPolicy


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str = ""
    defense: str = ""
    # free-form diagnostic payload (e.g. which envelope capability matched); goes to the trajectory log
    detail: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def allow(reason: str = "", **detail) -> "Decision":
        return Decision(Verdict.ALLOW, reason, detail=detail)

    @staticmethod
    def block(reason: str, **detail) -> "Decision":
        return Decision(Verdict.BLOCK, reason, detail=detail)

    @staticmethod
    def escalate(reason: str, **detail) -> "Decision":
        return Decision(Verdict.ESCALATE, reason, detail=detail)


@dataclass(frozen=True)
class ProposedCall:
    """A tool call the agent wants to make, *before* it executes."""
    function: str
    args: dict[str, Any]
    call_id: str | None = None
    step: int = 0  # index of this call within the episode


@dataclass
class Observation:
    """What a defense sees after a call is resolved (executed or blocked)."""
    call: ProposedCall
    decision: Decision
    executed: bool
    result_text: str | None
    error: str | None


@dataclass
class DefenseContext:
    """Everything a defense is allowed to look at when deciding.

    Deliberately excludes the injection-task ground truth: a defense must never see the attacker goal.
    """
    suite: str
    user_query: str
    history: list[dict]                    # AgentDojo ChatMessage dicts so far (system, user, assistant, tool)
    tool_specs: dict[str, dict]            # tool name -> JSON schema of params + description
    # Provenance: for each prior tool result, the text it returned. Lets taggers trace arg values to sources.
    tool_outputs: list[tuple[str, str]] = field(default_factory=list)  # (tool_name, output_text)
    extra: dict[str, Any] = field(default_factory=dict)
