"""Replay attack: play a fixed library of payloads the LLM attacker wrote in earlier runs.

The LLM attacker (ipi.attacks.adaptive) declined most of its attempts, so "budget 10" meant a different number of
real attacks for each defense. Here every defense faces the SAME payloads for a task pair, in the same order
(strongest first: see scripts/build_replay_library.py), which makes the comparison paired.

This is a transfer attack, not an adaptive one: nothing is learned from the defense under test. Many payloads were
written against a different defense than the one they are replayed on. Attempt 0 is the optional static seed.
A pair with fewer than budget-1 payloads in the library simply gets fewer attempts (generate returns None).
"""
from __future__ import annotations

import functools
import json

from ipi.attacks.base import Attack, AttackTask, Feedback


@functools.cache
def load_library(path: str) -> dict[tuple[str, str, str], list[dict]]:
    lib = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            lib[(r["suite"], r["user_task"], r["injection_task"])] = r["payloads"]
    return lib


class ReplayAttack(Attack):
    feedback_level = "outcome"  # nothing is used from the feedback; its length is the attempt counter

    def __init__(self, library: str = "data/replay_payloads.jsonl", budget: int = 10, seed: Attack | None = None):
        self.library, self.budget, self.seed = library, budget, seed
        self.name = "replay"
        self.last_meta: dict = {}

    def generate(self, task: AttackTask, defense_spec: dict, feedback: list[Feedback]) -> dict[str, str] | None:
        i = len(feedback)
        if self.seed is not None:
            if i == 0:
                self.last_meta = {"strategy": f"seed:{self.seed.name}"}
                return self.seed.generate(task, defense_spec, feedback)
            i -= 1
        pool = load_library(self.library).get((task.suite, task.user_task_id, task.injection_task_id), [])
        if i >= len(pool):
            return None  # library exhausted for this pair
        p = pool[i]
        self.last_meta = {"strategy": "replay", "library_index": i, "sources": p["sources"],
                          "succeeded_before": p["succeeded_before"]}
        return dict(p["injections"])
