"""Uniform attack interface. The ONE signature that separates a static attacker from an adaptive one:

    generate(task, defense_spec, feedback_history) -> {injection_vector_id: payload}

`defense_spec` = Defense.spec(): the white-box view (policy grammar, extractor prompt, thresholds).
`feedback_history` = what the attacker learned from earlier attempts within its query budget.

INTERFACE OWNER: Infra (signature) / Attack workstream (implementations).
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


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
        return {v: payload for v in task.vectors}
