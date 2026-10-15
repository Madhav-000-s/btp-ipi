"""Static (non-adaptive) attacks: AgentDojo's registered attacks, used as the baseline column.
budget = 1 and they ignore defense_spec / feedback, which is exactly what makes them static.
"""
from __future__ import annotations

from types import SimpleNamespace

from agentdojo.attacks.attack_registry import load_attack
from agentdojo.models import MODEL_NAMES

from ipi.attacks.base import Attack, AttackTask, Feedback

# AgentDojo 0.1.35 only knows Claude 3.x ids; address current Claude models as "Claude", as its published runs did.
for _m in ("claude-haiku-5", "claude-sonnet-5", "claude-opus-5", "claude-opus-4", "claude-fable-5"):
    MODEL_NAMES.setdefault(_m, "Claude")


class AgentDojoAttack(Attack):
    def __init__(self, attack_name: str, suite, model_name: str):
        self.name = attack_name
        self._suite = suite
        target = SimpleNamespace(name=model_name)
        try:
            self._impl = load_attack(attack_name, suite, target)
        except ValueError:
            # model name not in AgentDojo's MODEL_NAMES table -> use the variant that doesn't address the model
            fallback = attack_name + "_no_model_name" if attack_name == "important_instructions" else attack_name
            self._impl = load_attack(fallback, suite, SimpleNamespace(name="local"))

    def generate(self, task: AttackTask, defense_spec, feedback: list[Feedback]) -> dict[str, str]:
        ut = self._suite.get_user_task_by_id(task.user_task_id)
        it = self._suite.get_injection_task_by_id(task.injection_task_id)
        return self._impl.attack(ut, it)
