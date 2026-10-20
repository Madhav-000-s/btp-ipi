"""Attack registry.

  attacks:
    - important_instructions                       # any AgentDojo attack name -> static baseline
    - {name: template_adaptive, budget: 3}         # offline adaptive baseline (selection: round_robin | ucb)
    - {name: adaptive, provider: openai, model: gpt-4o-mini-2024-07-18, budget: 10,
       strategies: [living_off_the_land, envelope_generation, branch_steering], feedback_level: trace,
       selection: ucb, defense_mode: auto}         # defense_mode: null | progent | camel | auto
"""
from __future__ import annotations

from ipi.attacks.adaptive import AdaptiveLLMAttack, TemplateAdaptiveAttack
from ipi.attacks.base import Attack, AttackTask, Feedback
from ipi.attacks.static import AgentDojoAttack


def build_attack(spec: str | dict, suite, model_name: str) -> Attack:
    p = {"name": spec} if isinstance(spec, str) else dict(spec)
    n = p["name"]
    if n == "adaptive":
        a = AdaptiveLLMAttack(p["provider"], p["model"], p.get("strategies"), p.get("budget", 10),
                              p.get("feedback_level", "trace"), p.get("temperature", 0.7),
                              p.get("defense_mode"), p.get("selection", "ucb"))
    elif n == "template_adaptive":
        a = TemplateAdaptiveAttack(p.get("budget", 3), p.get("selection", "round_robin"),
                                   p.get("feedback_level", "trace"))
    else:
        a = AgentDojoAttack(n, suite, model_name)
    if "label" in p:
        a.name = p["label"]
    return a
