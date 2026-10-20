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
