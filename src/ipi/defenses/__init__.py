"""Defense registry. Configs refer to defenses by name + params:

  defenses:
    - none
    - {name: tool_filter, selector: oracle}
    - {name: policy}
    - {name: envelope, extractor: oracle, pin: query}
    - {name: envelope, extractor: llm, provider: openai, model: gpt-4o-mini-2024-07-18, unpinned_untrusted: escalate}

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
    return EnvelopeMonitor(extractor, p.get("unpinned_untrusted", "escalate"), p.get("use_provenance", True))


BUILDERS = {
    "none": lambda p: NoDefense(),
    "tool_filter": lambda p: ToolFilter(p.get("selector", "oracle"), p.get("provider"), p.get("model")),
    "policy": lambda p: PolicyDefense(p.get("policy_file")),
    "envelope": _envelope,
    "chain": lambda p: Chain([build_defense(d) for d in p["defenses"]]),
}


def build_defense(spec: str | dict) -> Defense:
    p = {"name": spec} if isinstance(spec, str) else dict(spec)
    d = BUILDERS[p["name"]](p)
    if "label" in p:
        d.name = p["label"]
    return d
