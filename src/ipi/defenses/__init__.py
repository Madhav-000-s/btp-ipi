"""Defense registry. Configs refer to defenses by name + params:

  defenses:
    - none
    - {name: tool_filter, selector: oracle}
    - {name: policy}
    - {name: envelope, extractor: oracle, pin: query}
    - {name: envelope, extractor: llm, provider: openai, model: gpt-4o-mini-2024-07-18, unpinned_untrusted: escalate}
    - {name: progent, provider: anthropic, model: claude-haiku-5-5}     # authors' secagent; update: false to freeze
    - {name: camel}                     # authors' CaMeL; replaces the agent loop; policies: false / eval_mode: STRICT
    - {name: ifc, mode: args | context}                                 # FIDES/RTBAS-style taint baselines

To add a defense (e.g. a CaMeL or Progent reproduction): implement ipi.defenses.base.Defense and register
a builder below. Nothing else in the harness changes.
"""
from __future__ import annotations

from ipi.defenses.base import Chain, Defense
from ipi.defenses.baselines import NoDefense, PolicyDefense, ToolFilter
from ipi.defenses.envelope.extractor import LLMExtractor, OracleExtractor
from ipi.defenses.envelope.monitor import EnvelopeMonitor


def _envelope(p: dict) -> Defense:
    ex = p.get("extractor", "oracle")
    if ex == "oracle":
        extractor = OracleExtractor(pin=p.get("pin", "query"))
    elif ex == "llm":
        extractor = LLMExtractor(p["provider"], p["model"], p.get("require_values_in_query", True))
    else:
        raise ValueError(f"unknown extractor {ex}")
    # v2 features, each an ablation switch (all on by default): record_trust, user_stated, delegation, recovery,
    # grounding
    return EnvelopeMonitor(extractor, p.get("unpinned_untrusted", "escalate"), p.get("use_provenance", True),
                           p.get("record_trust", True), p.get("user_stated", True), p.get("delegation", True),
                           p.get("recovery", True), p.get("grounding", True))


BUILDERS = {
    "none": lambda p: NoDefense(),
    "tool_filter": lambda p: ToolFilter(p.get("selector", "oracle"), p.get("provider"), p.get("model")),
    "policy": lambda p: PolicyDefense(p.get("policy_file")),
    "envelope": _envelope,
    "chain": lambda p: Chain([build_defense(d) for d in p["defenses"]]),
    "progent": lambda p: _progent(p),
    "camel": lambda p: _camel(p),
    "ifc": lambda p: _ifc(p),
}


def _camel(p: dict) -> Defense:
    from ipi.defenses.camel import CamelDefense  # imports the authors' camel package; builds its own pipeline
    return CamelDefense(p.get("policies", True), p.get("eval_mode", "NORMAL"), p.get("max_attempts", 10),
                        p.get("q_retries", 10))


def _progent(p: dict) -> Defense:
    from ipi.defenses.progent import ProgentDefense  # imports the authors' secagent package
    return ProgentDefense(p["provider"], p["model"], p.get("update", True))


def _ifc(p: dict) -> Defense:
    from ipi.defenses.ifc import IFCTaint
    return IFCTaint(p.get("mode", "args"))


def build_defense(spec: str | dict) -> Defense:
    p = {"name": spec} if isinstance(spec, str) else dict(spec)
    d = BUILDERS[p["name"]](p)
    if "label" in p:
        d.name = p["label"]
    return d
