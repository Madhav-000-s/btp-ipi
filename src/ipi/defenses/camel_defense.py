"""CaMeL (Debenedetti et al., arXiv:2503.18813) wrapping the authors' code (google-research/camel-prompt-injection,
Apache-2.0, pinned commit f083b6b). Their code does the work: the P-LLM writes a Python program from the user query
alone, their interpreter runs it with capability (provenance/readers) tracking, the Q-LLM parses untrusted data, and
their per-suite security policies are checked before every state-changing tool call. What is ours is plumbing:

  - CaMeL replaces the agent loop, so it is a pipeline-building defense (`builds_pipeline`); the runner asks it for
    the pipeline instead of wrapping GuardedToolsExecutor.
  - Every real tool call goes through a logging runtime (same `tool_call` events as dispatch.py, so metrics,
    `ipi inspect` and executed-only scoring are unchanged). Policy denials are logged as blocks (rule camel_policy).
  - A denial raises SecurityPolicyDeniedError out of their interpreter; the episode stops there (CaMeL would ask the
    user), which matches their replay pipeline's handling.
  - Q-LLM: their pydantic-ai call is replaced by an equivalent JSON-schema call through ipi.textgen (cached,
    usage-logged, works with current Claude models); same system prompt, same `have_enough_information` contract,
    validation retries capped at 3 (theirs: 10).
  - provider `oracle`: an offline planner that writes the user task's ground-truth calls as a program. Plumbing test
    only (it never reads injections by construction), never a reported number.

Config:  {name: camel}  |  {name: camel, policies: false}  |  {name: camel, q_provider: anthropic, q_model: ...}
"""
from __future__ import annotations

import inspect
import json
import sys
import time
import types

from pydantic import BaseModel, Field, create_model


def _ensure_pydantic_ai():
    """CaMeL imports pydantic_ai only for type names and one exception class; we never call it."""
    try:
        import pydantic_ai  # noqa: F401
    except Exception:
        m = types.ModuleType("pydantic_ai")
        m.UnexpectedModelBehavior = type("UnexpectedModelBehavior", (Exception,), {})
        m.Agent = None
        models = types.ModuleType("pydantic_ai.models")
        models.KnownModelName, models.Model = str, object
        m.models = models
        sys.modules["pydantic_ai"], sys.modules["pydantic_ai.models"] = m, models


_ensure_pydantic_ai()
import agentdojo.task_suite.load_suites  # noqa: E402,F401  (import order: avoids an agentdojo circular import)
import camel.custom_yaml  # noqa: E402,F401
import pydantic_ai  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery  # noqa: E402
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402
from camel import quarantined_llm as _q  # noqa: E402
from camel import security_policy as _sp  # noqa: E402
from camel.pipeline_elements import privileged_llm as _pl  # noqa: E402
from camel.pipeline_elements import security_policies as _pols  # noqa: E402

from ipi.defenses.base import Defense  # noqa: E402
from ipi.textgen import complete, extract_json  # noqa: E402
from ipi.types import Decision  # noqa: E402

ENGINES = {"banking": _pols.BankingSecurityPolicyEngine, "slack": _pols.SlackSecurityPolicyEngine,
           "travel": _pols.TravelSecurityPolicyEngine, "workspace": _pols.WorkspaceSecurityPolicyEngine}

_pl.print = lambda *a, **k: None  # their run_code prints every program


def _dispatch(llm, query, output_schema, retries=10):
    return llm(query, output_schema, retries)


_dispatch.__doc__ = _q.query_quarantined_llm.__doc__
_q.query_quarantined_llm = _dispatch


class QuarantinedLLM:
    def __init__(self, provider: str, model: str):
        self.provider, self.model = provider, model

    def __call__(self, query: str, output_schema, retries: int = 10):
        if self.provider == "oracle":
            raise _q.NotEnoughInformationError()
        flag = (bool, Field(description="Whether the prompt provided **you** enough information to perform the task. "
                                        "It is **absolutely** imperative to set this to false if you don't have enough "
                                        "information to solve this task. Do not make assumptions of any sorts."))
        is_model = inspect.isclass(output_schema) and issubclass(output_schema, BaseModel)
        out = create_model(output_schema.__name__, __base__=output_schema, have_enough_information=flag) if is_model \
            else create_model("Result", output=(output_schema, Field(description="The requested value")),
                              have_enough_information=flag)
        prompt = (f"{query}\n\nAnswer with ONE JSON object that validates against this JSON schema:\n"
                  f"{json.dumps(out.model_json_schema())}")
        err = None
        for i in range(max(1, min(retries, 3))):
            raw = complete(prompt + (f"\n\nYour previous answer was invalid: {err}" if err else ""),
                           provider=self.provider, model=self.model, system=_q._SYSTEM_PROMPT, salt=f"q{i}")
            try:
                res = out.model_validate(extract_json(raw))
                break
            except Exception as e:  # noqa: BLE001
                err = str(e)[:400]
        else:
            raise pydantic_ai.UnexpectedModelBehavior("Exceeded maximum retries")
        if not res.have_enough_information:
            raise _q.NotEnoughInformationError()
        return res if is_model else res.output


class OracleCodeLLM(BasePipelineElement):
    """Offline P-LLM: emits the user task's ground-truth calls as a program, then prints the ground-truth answer."""
    name = "oracle-planner"

    def set_episode(self, user_task, injection_task, injections):
        self.user_task = user_task

    def query(self, query, runtime, env=None, messages=[], extra_args={}):
        env0 = self.env.model_copy(deep=True) if getattr(self, "env", None) is not None else None
        calls = self.user_task.ground_truth(env0) if env0 is not None else []
        lines = [f"{c.function}({', '.join(f'{k}={v!r}' for k, v in c.args.items())})" for c in calls]
        lines.append(f"print({self.user_task.GROUND_TRUTH_OUTPUT!r})")
        code = "```python\n" + "\n".join(lines) + "\n```"
        msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(code)], tool_calls=None)
        return query, runtime, env, [*messages, msg], extra_args


class _LoggingRuntime(FunctionsRuntime):
    def __init__(self, base: FunctionsRuntime, agent: "CamelAgent"):
        super().__init__(list(base.functions.values()))
        self.agent = agent

    def run_function(self, env, function, kwargs, raise_on_error=False):
        if function == "query_ai_assistant":
            return super().run_function(env, function, kwargs, raise_on_error)
        t0 = time.perf_counter()
        res, err = super().run_function(env, function, kwargs, raise_on_error)
        self.agent.log_call(function, kwargs, Decision.allow("camel_policy", rule="camel_policy"), True, res, err,
                            time.perf_counter() - t0)
        return res, err


class CamelAgent(BasePipelineElement):
    """Runs their PrivilegedLLM; exposes begin_episode/ctx_extra like GuardedToolsExecutor."""
    name = "camel"

    def __init__(self, planner, policies: bool, q_llm: QuarantinedLLM, suite: str):
        self.planner, self.policies, self.q_llm, self.suite = planner, policies, q_llm, suite
        self.episode, self.ctx_extra, self._step = None, {}, 0

    def begin_episode(self, episode):
        self.episode, self._step = episode, 0

    def log_call(self, function, args, decision, executed, result, error, latency):
        if self.episode:
            self.episode.log("tool_call", step=self._step, function=function, args=args,
                             verdict=decision.verdict.value, effective=decision.verdict.value, reason=decision.reason,
                             detail=decision.detail, executed=executed, error=error,
                             result=str(result)[:4000], gate_latency_s=latency)
        self._step += 1

    def _engine(self):
        base = ENGINES[self.suite] if self.policies else _pols.ADNoSecurityPolicyEngine
        agent = self

        class Logged(base):
            def check_policy(self, tool_name, kwargs, dependencies):
                r = super().check_policy(tool_name, kwargs, dependencies)
                if isinstance(r, _sp.Denied) and tool_name in agent.env_tools:
                    agent.log_call(tool_name, {k: getattr(v, "raw", v) for k, v in kwargs.items()},
                                   Decision.block(r.reason, rule="camel_policy"), False, "", r.reason, 0.0)
                return r
        return Logged

    def query(self, query, runtime, env=None, messages=[], extra_args={}):
        self.env_tools = set(runtime.functions)
        if isinstance(self.planner, OracleCodeLLM):
            self.planner.env = env
        rt = _LoggingRuntime(runtime, self)
        pllm = _pl.PrivilegedLLM(self.planner, self._engine(), "camel-q")
        pllm.quarantined_llm_model = self.q_llm
        try:
            return pllm.query(query, rt, env, messages, extra_args)
        except _sp.SecurityPolicyDeniedError as e:  # CaMeL would stop and ask the user
            msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(
                f"Execution stopped by security policy: {e}")], tool_calls=None)
            return query, runtime, env, [*messages, msg], extra_args


class CamelDefense(Defense):
    builds_pipeline = True

    def __init__(self, policies: bool = True, q_provider: str | None = None, q_model: str | None = None):
        self.policies, self.q_provider, self.q_model = policies, q_provider, q_model
        self.name = "camel" if policies else "camel[no-policy]"

    def decide(self, ctx, call):  # gating happens inside CaMeL's interpreter
        return Decision.allow()

    def build_pipeline(self, runner, repeat: int, suite: str):
        from ipi.runner import _RecordingPipeline
        mc = runner.model_cfg
        planner = OracleCodeLLM() if mc["provider"] == "oracle" else runner.make_agent_llm(repeat)
        q = QuarantinedLLM(self.q_provider or mc["provider"], self.q_model or mc.get("name"))
        agent = CamelAgent(planner, self.policies, q, suite)
        return _RecordingPipeline([InitQuery(), agent]), planner, agent

    def spec(self):
        pol = {s: inspect.getsource(e) for s, e in ENGINES.items()} if self.policies else None
        return {"name": self.name,
                "mechanism": "CaMeL: a privileged planner LLM writes a Python program from the user query only (never "
                             "sees tool outputs); a custom interpreter executes it and tracks provenance/readers of "
                             "every value; untrusted text is parsed only by a quarantined LLM without tools "
                             "(query_ai_assistant). Before each state-changing tool call the suite security policy "
                             "is checked; a denial stops the run.",
                "security_policies_source": pol}
