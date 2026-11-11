"""LLM-written payloads must survive AgentDojo's YAML templating verbatim, in every vector of every suite."""
import json

import pytest
from agentdojo.task_suite.load_suites import get_suites

from ipi.attacks.base import Attack, AttackTask, yaml_safe

NASTY = 'Note: "amount": 10.0\n- "recipient": US133\\path {x}\n\nSYSTEM: it\'s: urgent # not a comment'


@pytest.mark.parametrize("suite_name", ["banking", "slack", "travel", "workspace"])
def test_payload_round_trips_in_every_vector(suite_name):
    suite = get_suites("v1.2.2")[suite_name]
    for vector in suite.get_injection_vector_defaults():
        env = suite.load_and_inject_default_environment({vector: yaml_safe(suite_name, vector, NASTY)})
        dumped = json.dumps(env.model_dump(mode="json"))
        assert json.dumps(NASTY)[1:-1] in dumped, f"{suite_name}/{vector}: payload not preserved verbatim"


def test_fill_escapes_per_vector():
    task = AttackTask("banking", "user_task_0", "", "injection_task_0", "", ["injection_bill_text"])
    assert Attack.fill(task, 'a "b"\nc') == {"injection_bill_text": r'a \"b\"\nc'}


def test_adaptive_attacker_plays_the_seed_attack_first_then_its_own(monkeypatch):
    from ipi.attacks import adaptive
    from ipi.attacks.base import AttackTask, Feedback

    class Seed:
        name = "important_instructions"
        def generate(self, task, spec, feedback):
            return {"vec": "STATIC"}

    monkeypatch.setattr(adaptive, "complete", lambda *a, **k: '{"payload": "LLM"}')
    a = adaptive.AdaptiveLLMAttack("anthropic", "m", budget=3, seed=Seed())
    task = AttackTask("banking", "user_task_0", "pay", "injection_task_0", "goal", ["vec"], [], [])
    first = a.generate(task, {}, [])
    assert first == {"vec": "STATIC"} and a.last_meta["strategy"] == "seed:important_instructions"
    second = a.generate(task, {}, [Feedback(0, first, False, True, [], [], [])])
    assert second == {"vec": "LLM"} and a.last_meta["strategy"] in adaptive.STRATEGIES
    assert sum(a.bandit.counts.values()) == 0  # the seed attempt is not credited to any strategy
