"""LLM backends.

- `make_llm(provider, model)` : real models via AgentDojo (openai, anthropic, google, together, local, vllm);
  current Claude models go through `ClaudeLLM` instead of AgentDojo's AnthropicLLM (see its docstring)
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
import re
import sqlite3
import threading
from collections.abc import Sequence
from pathlib import Path

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, get_text_content_as_str, text_content_block_from_string


def make_llm(provider: str, model: str, model_id: str | None = None, tool_delimiter: str = "tool",
             effort: str | None = None):
    if provider == "anthropic" and not _legacy_claude(model):
        llm = ClaudeLLM(model, effort=effort)
    elif provider == "openai-compat":
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


_USAGE_LOCK = threading.Lock()


def log_usage(model: str, usage, role: str, stop_reason: str | None = None,
              path: str = "results/usage.jsonl") -> None:
    """One line per real (uncached) API call, so spend can be computed from tokens rather than guessed.
    stop_reason is kept so refusals (an attacker that silently writes nothing) show up in the log."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    rec = {"model": model, "role": role, "input": usage.input_tokens, "output": usage.output_tokens,
           "cache_read": getattr(usage, "cache_read_input_tokens", 0) or 0, "stop_reason": stop_reason}
    with _USAGE_LOCK, open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")


def _legacy_claude(model: str) -> bool:
    """Claude 3.x: AgentDojo's own AnthropicLLM (temperature 0, 1024 max tokens) is what its published runs used."""
    return model.startswith("claude-3")


def accepts_sampling_params(model: str) -> bool:
    """Current Claude models (Haiku/Sonnet/Opus 5.x, Opus 4.7+) reject non-default temperature/top_p with a 400."""
    return not re.match(r"claude-(haiku|sonnet|opus|fable|mythos)-5|claude-opus-4-[78]", model)


class ClaudeLLM(BasePipelineElement):
    """Agent backbone for current Claude models. AgentDojo 0.1.35's AnthropicLLM sends temperature=0.0 (a 400 on
    these models) and caps output at 1024 tokens, which adaptive thinking (on by default) can exhaust before the
    tool call. Reuses AgentDojo's message conversion so thinking blocks round-trip unchanged."""

    def __init__(self, model: str, effort: str | None = None, max_tokens: int = 16000):
        import anthropic
        self.client = anthropic.Anthropic()
        self.model, self.effort, self.max_tokens = model, effort, max_tokens

    def query(self, query, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages=[], extra_args={}):
        from agentdojo.agent_pipeline.llms.anthropic_llm import (
            _anthropic_to_assistant_message, _conversation_to_anthropic, _function_to_anthropic)

        system, msgs = _conversation_to_anthropic(messages)
        kwargs = {"system": system} if system else {}
        if self.effort:
            kwargs["output_config"] = {"effort": self.effort}
        tools = [_function_to_anthropic(t) for t in runtime.functions.values()]
        if tools:
            kwargs["tools"] = tools
        with self.client.messages.stream(model=self.model, max_tokens=self.max_tokens, messages=msgs,
                                         **kwargs) as stream:
            completion = stream.get_final_message()
        log_usage(self.model, completion.usage, "agent", completion.stop_reason)
        out =_anthropic_to_assistant_message(completion)
        if out["tool_calls"]:
            out["tool_calls"] = [tc for tc in out["tool_calls"] if re.match(r"^[a-zA-Z0-9_-]{1,64}$", tc.function)]
        return query, runtime, env, [*messages, out], extra_args


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
