# Threat model (DRAFT v0 — sign off with the guide before running reported experiments)

Nothing reported is valid until this is frozen. Changing it after seeing results invalidates them.

## System
- Single LLM agent, tool calling, AgentDojo v1.2.2 suites (workspace, travel, banking, slack), mock tools.
- The **user** is trusted. The **user query** is trusted. **Tool outputs** are untrusted (may contain attacker text).
- The defense sits at the tool-call boundary (`GuardedToolsExecutor`). It sees `DefenseContext` only.

## Attacker
| Knob | Value | Config field |
|---|---|---|
| Injection point | Only the AgentDojo injection vectors the user task actually exposes | (fixed) |
| Knowledge of defense | **White-box on mechanism**: code, policies, extractor prompt, thresholds (`Defense.spec()`) | — |
| Knowledge of per-episode state | **No**: does not see the extracted envelope or the model's hidden reasoning | — |
| Knowledge of task | Sees the user prompt and its own goal + goal tool calls | `AttackTask` |
| Observation per attempt | Block/escalate reasons + executed call names | `feedback_level: trace` |
| Query budget B | 10 attempts per (user task, injection task) pair; stop at first success | `budget` |
| Attacker model | Same family as agent backbone (state which) | `adaptive.model` |
| Goal | AgentDojo injection task `security()` returns True | — |

Weaker settings to also report: `feedback_level: outcome` (only success bit) and `none` (non-adaptive repeated sampling) — this isolates how much of the adaptive ASR comes from the feedback channel.

## Defender
- Does not see the injection task or attacker values. Policies may only use user-owned environment data.
- Escalation: reported under both `deny` (no human, conservative) and `allow` (always-approving human). The truth is in between; the *escalation rate* is reported as a separate usability cost.

## Metrics (all with Wilson 95% CI, ≥5 repeats for reported numbers)
Benign utility · utility under attack · ASR @ B · benign block/escalate rate · over-defense FPR on AgentDyn · gate latency · extra tokens.

## Explicitly out of scope
Direct prompt injection · multi-agent · multimodal · training-time defenses as our contribution (StruQ/SecAlign appear only as related work / optional backbone) · real (non-mock) tools.

## Open questions for the guide
1. Is B = 10 acceptable, or should we report an ASR-vs-budget curve (B = 1, 3, 10, 30)? (Recommended: curve.)
2. Is "same model family as the agent" acceptable for the attacker, or do we need a stronger attacker model?
3. Which backbone for final numbers given the API budget?
