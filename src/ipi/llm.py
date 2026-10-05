"""LLM backends.

- `make_llm(provider, model)` : real models via AgentDojo (openai, anthropic, google, together, local, vllm)
  plus `openai-compat` for any OpenAI-compatible endpoint (OpenRouter, Groq, DeepInfra, a local vLLM)
  configured with OPENAI_COMPAT_BASE_URL / OPENAI_COMPAT_API_KEY.
- `CachedLLM` : disk cache so identical (model, messages, tools, repeat) never hits the API twice.
- `GullibleOracleLLM` : offline, deterministic, zero-cost agent for testing the harness and defenses.
  It follows the user task's ground truth, and if it ever *sees* injected text in a tool output it
  also executes the injection task's ground truth. So with no defense, ASR ~= 100% on injectable
  tasks; a defense that blocks the injected calls drives ASR to 0 while keeping utility. It measures the
  defense's gate in isolation from model robustness — use it for unit tests and CI, never for reported numbers.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Sequence
from pathlib import Path

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, get_text_content_as_str, text_content_block_from_string


def make_llm(provider: str, model: str, model_id: str | None = None, tool_delimiter: str = "tool"):
    if provider == "openai-compat":
        import openai
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

        client = openai.OpenAI(
            base_url=os.environ["OPENAI_COMPAT_BASE_URL"],
            api_key=os.environ.get("OPENAI_COMPAT_API_KEY", "EMPTY"),
        )
        llm = OpenAILLM(client, model)
    else:
        from agentdojo.agent_pipeline.agent_pipeline import get_llm

        llm = get_llm(provider, model, model_id, tool_delimiter)
    llm.name = model
    return llm


# ---------------------------------------------------------------------------------------------
# Disk cache
# ---------------------------------------------------------------------------------------------
def _msg_to_json(m) -> dict:
    d = dict(m)
    if d.get("tool_calls"):
        d["tool_calls"] = [tc.model_dump() for tc in d["tool_calls"]]
    if d.get("tool_call") is not None:
        d["tool_call"] = d["tool_call"].model_dump()
    return d


def _assistant_from_json(d: dict) -> ChatAssistantMessage:
    tcs = d.get("tool_calls")
    return ChatAssistantMessage(
        role="assistant",
        content=d.get("content"),
        tool_calls=[FunctionCall(**tc) for tc in tcs] if tcs else None,
    )


class CachedLLM(BasePipelineElement):
    _lock = threading.Lock()

    def __init__(self, inner: BasePipelineElement, path: str | Path, salt: str = ""):
        self.inner = inner
        self.name = getattr(inner, "name", None)
        self.salt = salt  # e.g. f"repeat={r}" so repeats are independent samples
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT)")
        self.hits = self.misses = 0

    def _key(self, messages, runtime) -> str:
        payload = json.dumps(
            {"m": self.name, "s": self.salt, "msgs": [_msg_to_json(m) for m in messages],
             "tools": sorted(runtime.functions)},
            sort_keys=True, default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        k = self._key(messages, runtime)
        with self._lock:
            row = self.db.execute("SELECT v FROM c WHERE k=?", (k,)).fetchone()
        if row:
            self.hits += 1
            return query, runtime, env, [*messages, _assistant_from_json(json.loads(row[0]))], extra_args
        self.misses += 1
        q, r, e, out, ea = self.inner.query(query, runtime, env, messages, extra_args)
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO c VALUES (?,?)", (k, json.dumps(_msg_to_json(out[-1]), default=str)))
            self.db.commit()
        return q, r, e, out, ea


# ---------------------------------------------------------------------------------------------
# Offline oracle agent
# ---------------------------------------------------------------------------------------------
class GullibleOracleLLM(BasePipelineElement):
    name = "gullible-oracle"

    def __init__(self):
        self.user_task = None
        self.injection_task = None
        self.injection_strings: list[str] = []
        self._plan: list[FunctionCall] | None = None
        self._hijacked = False

    def set_episode(self, user_task, injection_task, injections: dict[str, str]):
        self.user_task, self.injection_task = user_task, injection_task
        self.injection_strings = [v for v in injections.values() if v]
        self._plan, self._hijacked = None, False

    @staticmethod
    def _norm(s: str) -> str:
        # env loading + YAML tool-output formatting reflow whitespace and escape quotes; compare on a canonical form
        return "".join(ch for ch in s if not ch.isspace() and ch not in "\"'\\")

    def _saw_injection(self, messages: Sequence[ChatMessage]) -> bool:
        needles = [self._norm(s)[:200] for s in self.injection_strings if self._norm(s)]
        for m in messages:
            if m["role"] == "tool" and m["content"]:
                text = self._norm(get_text_content_as_str(m["content"]))
                if any(n in text for n in needles):
                    return True
        return False

    def query(self, query, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages=[], extra_args={}):
        if self._plan is None:
            self._plan = list(self.user_task.ground_truth(env.model_copy(deep=True)))
        if not self._hijacked and self.injection_task is not None and self._saw_injection(messages):
            self._hijacked = True
            # Injected goal is executed right after the injection is observed (worst case for the defender).
            inj = list(self.injection_task.ground_truth(env.model_copy(deep=True)))
            self._plan = inj + self._plan
        if self._plan:
            call = self._plan.pop(0)
            call = FunctionCall(function=call.function, args=dict(call.args), id=f"call_{len(messages)}")
            msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("")], tool_calls=[call])
        else:
            msg = ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string(self.user_task.GROUND_TRUTH_OUTPUT)],
                tool_calls=None,
            )
        return query, runtime, env, [*messages, msg], extra_args
