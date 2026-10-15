"""Progent (Shi et al., arXiv:2504.11703) as a Defense, wrapping the authors' own `secagent` package
(github.com/sunblaze-ucb/progent, MIT, pinned in pyproject). Their code does the work: LLM policy generation
from the user query, argument checks (JSON schema / regex) on every call, and policy updates from tool results.
What is ours is plumbing only:

  - secagent keeps its policy in module globals; our runner is multi-threaded. Each defense instance loads its
    own private copy of secagent/tool.py (~1 ms), so episodes never share policy state and need no lock.
  - secagent's api_request sends temperature=0.0 (a 400 on current Claude models) and is uncached; each copy's
    api_request is routed through ipi.textgen.complete (cached, usage-logged, sampling-safe). Retries still bump
    the temperature argument, which keeps their retry semantics (a fresh sample) on models that accept it.
  - Always-allowed tools per suite are copied from Progent's AgentDojo fork (default_suites/v1/*/task_suite.py).
  - Missing args are filled from the tool schema's defaults before checking, matching their wrapper's
    `sig.bind(...).apply_defaults()`.

Deviation, deliberate: if policy generation fails after secagent's own retries, the episode keeps only the
always-allowed tools (fail closed) instead of crashing; the failure is recorded in debug_state.

Config:
  - {name: progent, provider: anthropic, model: claude-haiku-5-5}            # update on (their run.sh default)
  - {name: progent, provider: anthropic, model: claude-haiku-5-5, update: false}
"""
from __future__ import annotations

import copy
import importlib.util
import itertools

import secagent.tool

from ipi.defenses.base import Defense
from ipi.textgen import complete
from ipi.types import Decision, DefenseContext, Observation, ProposedCall

ALWAYS_ALLOWED = {
    "banking": ["get_most_recent_transactions"],  # + every no-arg tool (allow_all_no_arg_tools=True)
    "slack": ["get_channels", "read_channel_messages", "read_inbox", "get_users_in_channel"],
    "travel": [
        "get_user_information", "get_all_hotels_in_city", "get_hotels_prices", "get_rating_reviews_for_hotels",
        "get_hotels_address", "get_all_restaurants_in_city", "get_cuisine_type_for_restaurants",
        "get_restaurants_address", "get_rating_reviews_for_restaurants",
        "get_dietary_restrictions_for_all_restaurants", "get_contact_information_for_restaurants",
        "get_price_for_restaurants", "check_restaurant_opening_hours", "get_all_car_rental_companies_in_city",
        "get_car_types_available", "get_rating_reviews_for_car_rental", "get_car_fuel_options",
        "get_car_rental_address", "get_car_price_per_day", "search_calendar_events", "get_day_calendar_events",
        "get_flight_information",
    ],
    "workspace": [
        "get_unread_emails", "get_sent_emails", "get_received_emails", "get_draft_emails", "search_emails",
        "search_contacts_by_name", "search_contacts_by_email", "get_current_day", "search_calendar_events",
        "get_day_calendar_events", "search_files_by_filename", "get_file_by_id", "list_files", "search_files",
    ],
}
ALLOW_NO_ARG_TOOLS = {"banking"}

_COPIES = itertools.count()


def _private_secagent(provider: str, model: str):
    """A fresh module object for secagent/tool.py with its own globals (policy, tools, query)."""
    spec = importlib.util.spec_from_file_location(f"secagent._tool_{next(_COPIES)}", secagent.tool.__file__)
    m = importlib.util.module_from_spec(spec)
    m.__package__ = "secagent"          # its relative imports (.utils, .policy_analysis) are stateless
    m.print = lambda *a, **k: None      # it logs every policy to stderr; silence this copy only
    spec.loader.exec_module(m)
    m.policy_model = model              # their prompt / JSON-format branches key off this string
    m.ignore_update_error = True        # SECAGENT_IGNORE_UPDATE_ERROR=True in their run.sh
    m.api_request = lambda sys_prompt, user_prompt, temperature=0.0: complete(
        user_prompt, provider=provider, model=model, system=sys_prompt, temperature=temperature, max_tokens=16384)
    return m


def _progent_tools(tool_specs: dict[str, dict]) -> list[dict]:
    return [{"name": n, "description": s["description"], "args": s["parameters"].get("properties", {})}
            for n, s in tool_specs.items()]


class ProgentDefense(Defense):
    def __init__(self, provider: str, model: str, update: bool = True):
        self.provider, self.model, self.update_enabled = provider, model, update
        self.name = "progent" if update else "progent[no-update]"
        self.sa = _private_secagent(provider, model)
        self.defaults: dict[str, dict] = {}
        self.error: str | None = None

    def reset(self, ctx: DefenseContext) -> None:
        sa = self.sa = _private_secagent(self.provider, self.model)
        self.defaults = {n: {k: v["default"] for k, v in s["parameters"].get("properties", {}).items()
                             if "default" in v} for n, s in ctx.tool_specs.items()}
        self.error = None
        sa.update_available_tools(_progent_tools(ctx.tool_specs))
        sa.update_always_allowed_tools(ALWAYS_ALLOWED.get(ctx.suite, []),
                                       allow_all_no_arg_tools=ctx.suite in ALLOW_NO_ARG_TOOLS)
        try:
            sa.generate_security_policy(ctx.user_query)
        except Exception as e:  # see module docstring: fail closed to the always-allowed tools
            self.error = f"policy generation failed: {type(e).__name__}: {e}"[:300]

    def decide(self, ctx: DefenseContext, call: ProposedCall) -> Decision:
        try:
            self.sa.check_tool_call(call.function, {**self.defaults.get(call.function, {}), **call.args})
        except self.sa.ValidationError as e:
            return Decision.block(str(e)[:500], rule="progent_policy")
        return Decision.allow("progent_policy")

    def update(self, obs: Observation) -> None:
        if not self.update_enabled:
            return
        result = obs.result_text if obs.executed else (obs.error or "")
        self.sa.generate_update_security_policy([{"name": obs.call.function, "args": obs.call.args}],
                                                str([result]), manual_check=False)

    def debug_state(self):
        generated = {t: [p[2] for p in ps if p[0] == 100] for t, ps in (self.sa.security_policy or {}).items()}
        return {"policy": {t: a for t, a in generated.items() if a}, "error": self.error}

    def spec(self):
        sa = self.sa
        return {
            "name": self.name,
            "mechanism": "Progent privilege control. Before the episode an LLM writes a least-privilege policy from "
                         "the user query alone: which tools are allowed, with JSON-schema/regex restrictions on their "
                         "arguments. Every tool call is checked against it; a violation is blocked and the reason is "
                         "returned to the agent. " + ("After each tool result the LLM may update the policy using "
                         "the benign content of the result." if self.update_enabled else "The policy is fixed."),
            "always_allowed_tools": ALWAYS_ALLOWED,
            "policy_generation_prompt": sa.SYS_PROMPT,
            "policy_update_prompt": sa.SYS_PROMPT_2 if self.update_enabled else None,
            "policy_model": self.model,
        }
