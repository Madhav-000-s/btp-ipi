"""Information-flow (taint) baselines standing in for FIDES (Costa et al., 2025) and RTBAS (Zhong et al., 2025),
whose code is not released (docs/rtbas_fides.md). These are OUR approximations of their core rule, labelled as such:

  ifc[context]  FIDES-style integrity label on the whole context: once any tool output (untrusted) has entered the
                context, every consequential call (non-read, or a read with a sink) is low-integrity -> escalate.
                FIDES avoids this blow-up with variable hiding; without it this is the conservative bound.
  ifc[args]     RTBAS-style dependency screening: a consequential call escalates only if one of its argument values
                (sink OR payload, >= 4 chars) traces to tool output and not to the user query (substring provenance).

Both are provenance gates - the design the envelope monitor argues against - included to measure over-defense.
"""
from __future__ import annotations

from ipi.defenses.base import Defense
from ipi.defenses.envelope import provenance
from ipi.defenses.envelope.envelope import Effect, taxonomy
from ipi.types import Decision


class IFCTaint(Defense):
    def __init__(self, mode: str = "args"):
        assert mode in ("context", "args")
        self.mode = mode
        self.name = f"ifc[{mode}]"

    def decide(self, ctx, call):
        info = taxonomy(ctx.suite).get(call.function)
        if info is None or (info.effect == Effect.READ and not info.sinks):
            return Decision.allow(rule="read")
        if self.mode == "context":
            if ctx.tool_outputs:
                return Decision.escalate("context contains untrusted tool output", rule="tainted_context")
            return Decision.allow(rule="clean_context")
        for arg, v in call.args.items():
            src = provenance.sources_of(v, ctx.user_query, ctx.tool_outputs)
            bad = provenance.untrusted_only(src)
            if bad:
                return Decision.escalate(f"argument '{arg}' derives from untrusted tool output", rule="tainted_arg",
                                         arg=arg)
        return Decision.allow(rule="untainted")

    def spec(self):
        return {"name": self.name, "mechanism": __doc__}
