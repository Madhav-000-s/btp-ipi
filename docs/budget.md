# API spend log

Every real-model run goes here (team rule). Cost is computed from `results/usage.jsonl` token counts, not estimated.

| Date | Run | Model | Episodes | API calls | Tokens in / out | Cost |
|---|---|---|---|---|---|---|
| 2026-10-16 | `haiku_smoke` (banking, 3 user × 1 injection, none + envelope[llm]) | claude-haiku-5-5 ($0.10 / $0.50 per MTok) | 12 | 22 | 53,083 / 5,873 | $0.008 |
| 2026-10-16 | `haiku_static` (banking, 5 defenses × 2 static attacks + benign) | claude-haiku-5-5 | 1,520 | 707 | 2,389,106 / 320,857 | $0.399 |

| 2026-10-16 | `haiku_progent_smoke` (banking, 4 user × 2 injection, progent) | claude-haiku-5-5 | 12 | 28 | — | $0.015 |
| 2026-10-16 | `haiku_adaptive` first attempt — **invalid**, harness bug: LLM payloads broke AgentDojo's YAML templating; run crashed after 12 jobs (kept in `results/_invalid_*`, not reported) | claude-haiku-5-5 | ~110 | 661 | 1,598,703 / 409,877 | $0.365 |

API calls < episodes because the agent cache is keyed on the full conversation: defenses that leave the
conversation unchanged replay the same sample (paired comparison across defenses, at no extra cost).

**Running total: $0.79** (of $100 Anthropic credits)

| 2026-10-20 | `free_static_banking` (banking, 8 user x 4 injection, 6 defenses incl. Progent, CaMeL, envelope[llm]) | gemini-3.5-flash-lite (free tier) | 218 | ~500 (daily cap) | - | $0 |
| 2026-10-20 | `free_adaptive_banking` (policy vs UCB adaptive attacker, B = 10, 4 pairs; envelope[llm] cut off by quota) | gemini-3.1-flash-lite (free tier) | 40 valid | ~500 (daily cap) | - | $0 |
| 2026-10-16 | `haiku_adaptive_banking` (banking, 24 pairs, 4 defenses, B = 10; previously unlogged) | claude-haiku-5-5 | 886 | 2,264 | 6,460,515 / 1,071,652 | $1.18 |
| 2026-11-11 | `haiku_compliant_pilot` (system prompt told to obey tool results: still 0/24 with no defense) | claude-haiku-5-5 | 156 | - | - | $0.15 |
| 2026-11-11 | `haiku_hijacked_pilot` (agent_mode: hijacked; none = 83% static ASR, policy / envelope[llm] = 0%) | claude-haiku-5-5 | 148 | - | - | $0.13 |
| 2026-11-11 | `haiku_hijacked_smoke` (tool_filter, ifc, progent, camel in hijacked mode; 0 errors) | claude-haiku-5-5 | ~100 | - | - | $0.16 |
| 2026-11-11 | `haiku_hijacked_banking` (full banking, 9 defenses, static + seeded adaptive B = 10, agent_mode: hijacked; 1 network error in 2,736 jobs) | claude-haiku-5-5 | 2,736 | - | - | $16.36 |

| 2026-11-11 | `haiku_hijacked_v2_pilot` (fix check: compliant-victim attacker + confirming hijack turn; none 9/9) | claude-haiku-5-5 | ~115 | - | - | $0.18 |
| 2026-11-11 | `haiku_hijacked_banking_v2` (adaptive half rerun, working hijacked attacker, 9 defenses x 144 pairs, B = 10; 5 network errors in 1,440) | claude-haiku-5-5 | 1,440 | - | - | $14.77 |
| 2026-11-11 | `haiku_envelope_v2` (envelope v2: record trust, user-stated, delegation, recovery; static + adaptive B = 10; 5 network errors; adaptive ASR 1/144 and 2/142 via assembled IBANs) | claude-haiku-5-5 | 608 jobs | - | - | $4.35 |
| 2026-11-11 | `haiku_envelope_v3` (v2 + grounding rule; static + adaptive B = 10; adaptive ASR 0/142 for both extractors; 4 network errors) | claude-haiku-5-5 | 608 jobs | - | - | $4.25 |
| 2026-11-12 | `haiku_envelope_v3_ablation` (oracle extractor, one v3 rule off per row x 5; static + adaptive B = 10; 38 jobs lost to connection drops and rerun, $0.53 of the total) | claude-haiku-5-5 | 1,520 jobs | - | - | $10.68 |
| 2026-11-12 | `haiku_envelope_v3` repeats 1-4 (`configs/haiku_envelope_v3_r5.yaml`; 5 repeats in total, ASR 0/720 static and 0/720 adaptive for both extractors; 8 jobs lost to connection drops and rerun) | claude-haiku-5-5 | 2,436 jobs | - | - | $16.40 |

**Running total (corrected): $69.17** of $100 Anthropic credits. Runs now print their own spend and stop at `max_cost_usd`.
