# RTBAS and FIDES: availability check and what a faithful reimplementation needs

Checked October 2026 (paper pages, arXiv, GitHub search):

| Defense | Paper | Official code | Decision |
|---|---|---|---|
| RTBAS (Zhong et al., 2025, arXiv:2502.08966) | Robust Tool-Based Agent Systems: per-call dependency screening (LM-as-judge + attention-based saliency) to decide which tool outputs a call depends on; user confirmation when a call depends on untrusted/confidential data | No public release found | Approximate (`ifc[args]`) + this note |
| FIDES (Costa et al., Microsoft, 2025, arXiv:2505.23643) | Information-flow control for agents: confidentiality and integrity labels on every message, deterministic policies at tool calls, variable hiding (quarantined values) and constrained-decoding helpers to avoid label creep | No public release found | Approximate (`ifc[context]`) + this note |

## What our approximations keep and drop
- `ifc[context]` keeps FIDES's core integrity rule (a consequential action taken in a low-integrity context needs approval) but drops variable hiding, so its over-defense is an UPPER bound on FIDES's.
- `ifc[args]` keeps RTBAS's "does this call depend on untrusted output?" question but answers it with substring provenance instead of an LM judge / attention saliency, so it misses paraphrased flows (under-blocks) and over-matches short strings.

## A faithful reimplementation would need
1. FIDES: a label lattice (integrity x confidentiality, reader sets), labelled message history, the `hide`/`expand` variable mechanism with a quarantined sub-LLM, per-tool policies (P-T trusted action, P-F permitted flow), and the planner prompt changes. Est. 2-3 person-weeks; pipeline change similar to CaMeL.
2. RTBAS: an LM-judge relevance screener over each tool result, an attention-saliency variant (needs open-weights backbone, e.g. Llama), label propagation through the dependency graph, and the confirmation policy. Est. 2 person-weeks; the saliency variant cannot run on API-only models.

Thesis claim therefore: CaMeL and Progent are evaluated with the authors' code; RTBAS and FIDES are represented by clearly-labelled approximations of their decision rule.
