"""Uniform attack interface. The ONE signature that separates a static attacker from an adaptive one:

    generate(task, defense_spec, feedback_history) -> {injection_vector_id: payload}

`defense_spec` = Defense.spec(): the white-box view (policy grammar, extractor prompt, thresholds).
`feedback_history` = what the attacker learned from earlier attempts within its query budget.

INTERFACE OWNER: Infra (signature) / Attack workstream (implementations).
"""
from __future__ import annotations

import abc
import functools
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import agentdojo


@dataclass
class AttackTask:
    suite: str
    user_task_id: str
    user_prompt: str
    injection_task_id: str
    goal: str                           # the attacker's goal in natural language (InjectionTask.GOAL)
    vectors: list[str]                  # injection placeholders the agent will actually see for this user task
    tools: list[str] = field(default_factory=list)
    goal_calls: list[dict] = field(default_factory=list)  # ground-truth calls that achieve the goal (attacker knows its own goal)


@dataclass
class Feedback:
    attempt: int
    payload: dict[str, str]
    success: bool
    utility: bool
    blocked: list[dict]       # [{function, args, reason, rule}]  (only if feedback_level >= "trace")
    executed: list[dict]      # [{function, args}]
    escalated: list[dict]


class Attack(abc.ABC):
    name: str = "base"
    budget: int = 1           # attempts per (user_task, injection_task); runner stops at first success
    feedback_level: str = "trace"  # none | outcome | trace   (threat-model knob: how much the attacker observes)

    @abc.abstractmethod
    def generate(self, task: AttackTask, defense_spec: dict[str, Any], feedback: list[Feedback]) -> dict[str, str]:
        ...

    @staticmethod
    def fill(task: AttackTask, payload: str) -> dict[str, str]:
        """Payload for every vector, escaped for where the vector sits in the suite's YAML (see yaml_safe)."""
        return {v: yaml_safe(task.suite, v, payload) for v in task.vectors}


_PROBE = 'p"q\\r\nz: - s'


def _dq_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", r"\n")


@functools.cache
def _vector_contexts(suite: str) -> dict[str, str | None]:
    """vector id -> None if it sits inside a double-quoted YAML scalar, else the indentation of its line (block
    scalar). Decided empirically -- inject a probe escaped for double quotes and see whether it comes back verbatim --
    because some double-quoted scalars span several lines, which a line-by-line scan misreads."""
    from agentdojo.task_suite.load_suites import get_suites

    ts = get_suites("v1.2.2")[suite]
    root = Path(agentdojo.__file__).parent / "data" / "suites" / suite
    lines = [ln for f in root.rglob("*.yaml") if f.name != "injection_vectors.yaml"
             for ln in f.read_text(encoding="utf-8").splitlines()]
    probe = json.dumps(_PROBE)[1:-1]
    ctx: dict[str, str | None] = {}
    for vector in ts.get_injection_vector_defaults():
        try:
            env = ts.load_and_inject_default_environment({vector: _dq_escape(_PROBE)})
            if probe in json.dumps(env.model_dump(mode="json")):
                ctx[vector] = None
                continue
        except Exception:
            pass
        line = next(ln for ln in lines if "{" + vector + "}" in ln)
        ctx[vector] = line[: len(line) - len(line.lstrip())]
    return ctx


def yaml_safe(suite: str, vector: str, payload: str) -> str:
    """AgentDojo builds the environment with str.format on YAML text, so an LLM-written payload containing quotes,
    newlines or YAML structure breaks the parse (or silently changes the data). Escape it for its context so the
    agent sees the payload verbatim. AgentDojo's own static attacks do not go through here, so they stay as published."""
    indent = _vector_contexts(suite).get(vector)
    if indent is None:  # double-quoted scalar
        return _dq_escape(payload)
    return payload.replace("\n", "\n" + indent)  # block scalar: keep every line inside the block
