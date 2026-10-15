# API spend log

Every real-model run goes here (team rule). Cost is computed from `results/usage.jsonl` token counts, not estimated.

| Date | Run | Model | Episodes | API calls | Tokens in / out | Cost |
|---|---|---|---|---|---|---|
| 2026-10-16 | `haiku_smoke` (banking, 3 user × 1 injection, none + envelope[llm]) | claude-haiku-5-5 ($0.10 / $0.50 per MTok) | 12 | 22 | 53,083 / 5,873 | $0.008 |
| 2026-10-16 | `haiku_static` (banking, 5 defenses × 2 static attacks + benign) | claude-haiku-5-5 | 1,520 | 707 | 2,389,106 / 320,857 | $0.399 |

API calls < episodes because the agent cache is keyed on the full conversation: defenses that leave the
conversation unchanged replay the same sample (paired comparison across defenses, at no extra cost).

**Running total: $0.41** (of $100 Anthropic credits)
