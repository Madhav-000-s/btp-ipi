"""Instrumented dispatch layer: the single point where every tool call is gated and logged.

Replaces AgentDojo's ToolsExecutor inside the ToolsExecutionLoop. Every defense hooks in here.
INTERFACE OWNER: Infra.
"""
from __future__ import annotations

import time
from ast import literal_eval
from collections.abc import Sequence
from enum import Enum

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, get_text_content_as_str, text_content_block_from_string

from ipi.defenses.base import Defense
from ipi.trajectory import Episode
from ipi.types import Decision, DefenseContext, Observation, ProposedCall, Verdict


BLOCK_PREFIX = "Tool call blocked by security policy."


class EscalationPolicy(str, Enum):
    DENY = "deny"    # no human in the loop: escalation == block (conservative; default for reported numbers)
    ALLOW = "allow"  # optimistic human who always approves: upper bound on utility, lower bound on security


def tool_specs_from_runtime(runtime: FunctionsRuntime) -> dict[str, dict]:
    return {
        name: {"description": fn.description, "parameters": fn.parameters.model_json_schema()}
        for name, fn in runtime.functions.items()
    }


def tool_outputs_from_messages(messages: Sequence[ChatMessage]) -> list[tuple[str, str]]:
    out = []
    for m in messages:
        if m["role"] == "tool" and m.get("tool_call") is not None:
            out.append((m["tool_call"].function, get_text_content_as_str(m["content"] or [])))
    return out


class GuardedToolsExecutor(BasePipelineElement):
    """Drop-in replacement for agentdojo's ToolsExecutor that consults a Defense before every call."""

    name = "guarded_tools_executor"

    def __init__(
        self,
        defense: Defense,
        escalation: EscalationPolicy = EscalationPolicy.DENY,
        reveal_block_reason: bool = True,
    ):
        self.defense = defense
        self.escalation = escalation
        self.reveal_block_reason = reveal_block_reason
        self.episode: Episode | None = None
        self.ctx_extra: dict = {}  # runner-provided extras (e.g. oracle_calls for oracle baselines ONLY)
        self._ctx: DefenseContext | None = None
        self._step = 0

    # ---- episode lifecycle (driven by the runner) ----
    def begin_episode(self, episode: Episode) -> None:
        self.episode = episode
        self._ctx = None
        self._step = 0

    def _ensure_ctx(self, query: str, runtime: FunctionsRuntime, messages: Sequence[ChatMessage]) -> DefenseContext:
        if self._ctx is None:
            self._ctx = DefenseContext(
                suite=self.episode.suite if self.episode else "",
                user_query=query,
                history=list(messages),
                tool_specs=tool_specs_from_runtime(runtime),
                extra=dict(self.ctx_extra),
            )
            t0 = time.perf_counter()
            self.defense.reset(self._ctx)
            if self.episode:
                self.episode.log("defense_reset", defense=self.defense.name, latency_s=time.perf_counter() - t0,
                                 state=getattr(self.defense, "debug_state", lambda: None)())
        else:
            self._ctx.history = list(messages)
        self._ctx.tool_outputs = tool_outputs_from_messages(messages)
        return self._ctx

    # ---- main hook ----
    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args

        ctx = self._ensure_ctx(query, runtime, messages)
        results = []
        for tc in messages[-1]["tool_calls"]:
            if tc.function == EMPTY_FUNCTION_NAME or tc.function not in runtime.functions:
                results.append(self._tool_msg(tc, "", f"Invalid tool {tc.function} provided."))
                continue
            for k, v in tc.args.items():
                if isinstance(v, str) and is_string_list(v):
                    tc.args[k] = literal_eval(v)

            call = ProposedCall(function=tc.function, args=dict(tc.args), call_id=tc.id, step=self._step)
            self._step += 1

            t0 = time.perf_counter()
            decision = self.defense.decide(ctx, call)
            gate_latency = time.perf_counter() - t0
            effective = self._resolve(decision)

            if effective == Verdict.ALLOW:
                result, error = runtime.run_function(env, tc.function, tc.args)
                text = tool_result_to_str(result)
                results.append(self._tool_msg(tc, text, error))
                obs = Observation(call, decision, True, text, error)
            else:
                msg = BLOCK_PREFIX
                if self.reveal_block_reason and decision.reason:
                    msg += f" Reason: {decision.reason}"
                results.append(self._tool_msg(tc, "", msg))
                obs = Observation(call, decision, False, None, msg)

            self.defense.update(obs)
            if self.episode:
                self.episode.log(
                    "tool_call",
                    step=call.step,
                    function=call.function,
                    args=call.args,
                    verdict=decision.verdict.value,
                    effective=effective.value,
                    reason=decision.reason,
                    detail=decision.detail,
                    executed=obs.executed,
                    error=obs.error,
                    result=(obs.result_text or "")[:4000],
                    gate_latency_s=gate_latency,
                )
        return query, runtime, env, [*messages, *results], extra_args

    def _resolve(self, d: Decision) -> Verdict:
        if d.verdict == Verdict.ESCALATE:
            return Verdict.ALLOW if self.escalation == EscalationPolicy.ALLOW else Verdict.BLOCK
        return d.verdict

    @staticmethod
    def _tool_msg(tc, text: str, error: str | None) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string(text)],
            tool_call_id=tc.id,
            tool_call=tc,
            error=error,
        )
