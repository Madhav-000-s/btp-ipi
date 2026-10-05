"""Config-driven experiment runner: (suite x user_task x [injection_task] x attack x defense x repeat) grid.

Outputs to results/<run_name>/:
  events.jsonl   append-only trajectory log (every gated call, defense state, full message history)
  results.csv    one row per episode-final-attempt (what metrics.py consumes)
  manifest.json  pinned versions: agentdojo, benchmark version, python, git commit, full config
"""
from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.attacks.base_attacks import BaseAttack
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import get_text_content_as_str

from ipi.attacks import AttackTask, Feedback, build_attack
from ipi.defenses import build_defense
from ipi.dispatch import BLOCK_PREFIX, EscalationPolicy, GuardedToolsExecutor
from ipi.llm import CachedLLM, GullibleOracleLLM, make_llm
from ipi.llm import _msg_to_json
from ipi.trajectory import Episode, JsonlSink

RESULT_FIELDS = [
    "run_id", "suite", "user_task", "injection_task", "attack", "defense", "model", "repeat",
    "attempts", "utility", "attack_success", "n_calls", "n_blocked", "n_escalated", "block_rules",
    "gate_latency_s", "wall_s", "error",
]


@dataclass
class Job:
    suite: str
    user_task: str
    injection_task: str | None
    attack: Any       # spec (str|dict) or None for benign
    defense: Any      # spec
    repeat: int


class _Candidates(BaseAttack):
    """Reuse AgentDojo's ground-truth canary pass to find which injection vectors a user task exposes."""
    name = "_candidates"

    def attack(self, user_task, injection_task):
        raise NotImplementedError


class _RecordingPipeline(AgentPipeline):
    """Records the full conversation for logging, and returns a *scoring view* to AgentDojo.

    AgentDojo builds the function trace for security_from_traces (e.g. all Slack injection tasks) from the
    assistant's tool_calls - i.e. ATTEMPTED calls, including ones our defense blocked. Scored that way, a
    blocked attack counts as a success. The scoring view drops blocked calls so security is judged on
    EXECUTED calls only. The model's own context during the episode is untouched.
    """
    last_messages: list = []

    def query(self, query, runtime, env, messages=[], extra_args={}):
        q, r, e, msgs, ea = super().query(query, runtime, env, messages, extra_args)
        self.last_messages = list(msgs)
        blocked = {id(m["tool_call"]) for m in msgs
                   if m["role"] == "tool" and (m.get("error") or "").startswith(BLOCK_PREFIX)}
        if not blocked:
            return q, r, e, msgs, ea
        view = []
        for m in msgs:
            if m["role"] == "assistant" and m.get("tool_calls"):
                m = {**m, "tool_calls": [tc for tc in m["tool_calls"] if id(tc) not in blocked]}
            view.append(m)
        return q, r, e, view, ea


class Runner:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.run_name = cfg["run_name"]
        self.out = Path(cfg.get("out_dir", "results")) / self.run_name
        self.out.mkdir(parents=True, exist_ok=True)
        self.sink = JsonlSink(self.out / "events.jsonl")
        self.suites = get_suites(cfg.get("benchmark_version", "v1.2.2"))
        self.model_cfg = cfg["model"]
        self.model_name = self.model_cfg.get("name", "gullible-oracle")
        self._csv_lock = threading.Lock()
        self._cand: dict[str, _Candidates] = {}
        self._write_manifest()

    # ---------------- setup ----------------
    def _write_manifest(self):
        try:
            commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        except Exception:
            commit = ""
        (self.out / "manifest.json").write_text(json.dumps({
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "agentdojo_version": importlib.metadata.version("agentdojo"),
            "benchmark_version": self.cfg.get("benchmark_version", "v1.2.2"),
            "python": platform.python_version(),
            "git_commit": commit,
            "config": self.cfg,
        }, indent=2, default=str))

    def jobs(self) -> list[Job]:
        c = self.cfg
        jobs = []
        for sname in c["suites"]:
            suite = self.suites[sname]
            uts = c.get("user_tasks", {}).get(sname) if isinstance(c.get("user_tasks"), dict) else None
            its = c.get("injection_tasks", {}).get(sname) if isinstance(c.get("injection_tasks"), dict) else None
            uts = uts or list(suite.user_tasks)
            its = its or list(suite.injection_tasks)
            if c.get("limit_user_tasks"):
                uts = uts[: c["limit_user_tasks"]]
            if c.get("limit_injection_tasks"):
                its = its[: c["limit_injection_tasks"]]
            for r in range(c.get("repeats", 1)):
                for d in c["defenses"]:
                    if c.get("benign", True):
                        jobs += [Job(sname, u, None, None, d, r) for u in uts]
                    for a in c.get("attacks", []):
                        jobs += [Job(sname, u, i, a, d, r) for u in uts for i in its]
        return jobs

    def _pipeline(self, defense, repeat: int):
        mc = self.model_cfg
        if mc["provider"] == "oracle":
            llm = GullibleOracleLLM()
        else:
            inner = make_llm(mc["provider"], mc["name"], mc.get("model_id"), mc.get("tool_delimiter", "tool"))
            llm = CachedLLM(inner, self.cfg.get("cache", "results/cache/llm.sqlite"), salt=f"r{repeat}") \
                if self.cfg.get("use_cache", True) else inner
        executor = GuardedToolsExecutor(
            defense,
            EscalationPolicy(self.cfg.get("escalation", "deny")),
            self.cfg.get("reveal_block_reason", True),
        )
        sysmsg = defense.wrap_system_prompt(load_system_message(self.cfg.get("system_message")))
        p = _RecordingPipeline([SystemMessage(sysmsg), InitQuery(), llm,
                                ToolsExecutionLoop([executor, llm], max_iters=self.cfg.get("max_iters", 15))])
        p.name = self.model_name
        return p, llm, executor

    def _candidates(self, sname: str, user_task) -> list[str]:
        if sname not in self._cand:
            self._cand[sname] = _Candidates(self.suites[sname], None)
        return self._cand[sname].get_injection_candidates(user_task)

    # ---------------- one episode ----------------
    def _episode(self, job: Job, attack_name: str, attempt: int, injections: dict[str, str]):
        suite = self.suites[job.suite]
        ut = suite.get_user_task_by_id(job.user_task)
        it = suite.get_injection_task_by_id(job.injection_task) if job.injection_task else None
        defense = build_defense(job.defense)
        pipeline, llm, executor = self._pipeline(defense, job.repeat)
        ep = Episode(self.run_name, job.suite, job.user_task, job.injection_task, attack_name, defense.name,
                     self.model_name, job.repeat, attempt, self.sink)
        executor.begin_episode(ep)
        if getattr(defense, "needs_oracle", False):
            env = ut.init_environment(suite.load_and_inject_default_environment(injections))
            executor.ctx_extra["oracle_calls"] = ut.ground_truth(env)
        if isinstance(llm, GullibleOracleLLM):
            llm.set_episode(ut, it, injections)
        ep.log("episode_start", injections=injections)
        t0 = time.perf_counter()
        err = ""
        try:
            utility, security = suite.run_task_with_pipeline(pipeline, ut, it, injections)
        except Exception as e:  # never let one episode kill the grid
            utility, security, err = False, False, f"{type(e).__name__}: {e}"
            ep.log("error", traceback=traceback.format_exc())
        wall = time.perf_counter() - t0
        calls = ep.tool_events()
        ep.log("episode_end", utility=utility, attack_success=bool(security) if it else None, wall_s=wall,
               messages=[_msg_to_json(m) for m in pipeline.last_messages])
        return utility, (bool(security) if it else False), calls, wall, err, defense

    def run_job(self, job: Job) -> dict:
        suite = self.suites[job.suite]
        ut = suite.get_user_task_by_id(job.user_task)
        if job.injection_task is None:
            utility, _, calls, wall, err, defense = self._episode(job, "none", 0, {})
            return self._row(job, "none", defense.name, 1, utility, False, calls, wall, err)

        it = suite.get_injection_task_by_id(job.injection_task)
        attack = build_attack(job.attack, suite, self.model_name)
        env = ut.init_environment(suite.load_and_inject_default_environment({}))
        try:
            vectors = self._candidates(job.suite, ut)
        except ValueError:
            vectors = []
        task = AttackTask(job.suite, job.user_task, ut.PROMPT, job.injection_task, it.GOAL, vectors,
                          [t.name for t in suite.tools],
                          [{"function": c.function, "args": dict(c.args)} for c in it.ground_truth(env)])
        spec = build_defense(job.defense).spec()
        feedback: list[Feedback] = []
        total_wall, all_calls, last = 0.0, [], None
        for attempt in range(max(1, attack.budget)):
            visible = feedback if attack.feedback_level != "none" else []
            injections = attack.generate(task, spec, visible)
            utility, success, calls, wall, err, defense = self._episode(job, attack.name, attempt, injections)
            total_wall += wall
            all_calls = calls
            last = (utility, success, err, defense.name)
            if success or err:
                break
            feedback.append(Feedback(
                attempt, injections, success, utility,
                blocked=[{"function": c["function"], "args": c["args"], "reason": c["reason"],
                          "rule": c["detail"].get("rule")} for c in calls if c["verdict"] == "block"],
                executed=[{"function": c["function"], "args": c["args"]} for c in calls if c["executed"]],
                escalated=[{"function": c["function"], "reason": c["reason"]} for c in calls if c["verdict"] == "escalate"],
            ) if attack.feedback_level == "trace" else Feedback(attempt, injections, success, utility, [], [], []))
        utility, success, err, dname = last
        return self._row(job, attack.name, dname, attempt + 1, utility, success, all_calls, total_wall, err)

    def _row(self, job, attack_name, dname, attempts, utility, success, calls, wall, err) -> dict:
        return {
            "run_id": self.run_name, "suite": job.suite, "user_task": job.user_task,
            "injection_task": job.injection_task or "", "attack": attack_name, "defense": dname,
            "model": self.model_name, "repeat": job.repeat, "attempts": attempts,
            "utility": int(bool(utility)), "attack_success": int(bool(success)),
            "n_calls": len(calls), "n_blocked": sum(c["verdict"] == "block" for c in calls),
            "n_escalated": sum(c["verdict"] == "escalate" for c in calls),
            "block_rules": "|".join(sorted({c["detail"].get("rule", "") for c in calls if c["verdict"] != "allow"})),
            "gate_latency_s": round(sum(c["gate_latency_s"] for c in calls), 6), "wall_s": round(wall, 3),
            "error": err,
        }

    # ---------------- grid ----------------
    def run(self, workers: int | None = None) -> Path:
        jobs = self.jobs()
        csv_path = self.out / "results.csv"
        done = self._done_keys(csv_path)
        todo = [j for j in jobs if self._key(j) not in done]
        print(f"[{self.run_name}] {len(jobs)} jobs, {len(done)} already done, running {len(todo)}")
        new = not csv_path.exists()
        with open(csv_path, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=RESULT_FIELDS)
            if new:
                w.writeheader()
            workers = workers or self.cfg.get("workers", 1)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(self.run_job, j): j for j in todo}
                for n, fut in enumerate(as_completed(futs), 1):
                    row = fut.result()
                    row["_key"] = self._key(futs[fut])
                    with self._csv_lock:
                        w.writerow({k: row[k] for k in RESULT_FIELDS})
                        f.flush()
                        (self.out / "done_keys.txt").open("a").write(row["_key"] + "\n")
                    if n % 25 == 0 or n == len(todo):
                        print(f"  {n}/{len(todo)}")
        return csv_path

    @staticmethod
    def _key(j: Job) -> str:
        return hashlib.sha1(json.dumps([j.suite, j.user_task, j.injection_task, j.attack, j.defense, j.repeat],
                                       sort_keys=True, default=str).encode()).hexdigest()

    def _done_keys(self, csv_path: Path) -> set[str]:
        p = self.out / "done_keys.txt"
        return set(p.read_text().split()) if p.exists() else set()


def load_config(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text())
