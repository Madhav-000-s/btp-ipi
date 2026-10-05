# Team plan — next 3 weeks (from 6 Oct 2026)

Shared infra is done (harness, interfaces, logging, runner, metrics, baselines, envelope monitor v0, attacker v0).
The remaining work splits into four lanes with no file overlap. Every task has a "done when" so there's no ambiguity.

**Rules**
- `src/ipi/types.py`, `dispatch.py`, `defenses/base.py`, `attacks/base.py` are interfaces. Changes go through Madhav.
- `pytest -q` and `ipi run configs/quick.yaml` must pass before any merge.
- Adversarial separation: whoever builds the attacker does **not** design the monitor's rules.
- Log every API spend in `docs/budget.md` (date, run, model, approx cost).

---

## Madhav — Infra owner + monitor
1. Freeze `docs/threat_model.md` with the guide (budget B, attacker model, backbone). **Done when** signed off.
2. Wire the first real-model run: `configs/real_static.yaml` on banking. **Done when** no-defense ASR/utility is within a few points of AgentDojo's published number for the same model (Analysis confirms).
3. Monitor v1: LLM extractor quality pass on all 4 suites — compare `envelope[llm]` vs `envelope[oracle-query]` vs `envelope[oracle-all]`. **Done when** you can state where extraction loses utility (rule breakdown from `block_rules`).
4. Review every PR touching interfaces.

## Teammate 1 — Defense lane (reproductions)
1. Port **Progent** as a `Defense`: its released code is at github.com/sunblaze-ucb/progent; wrap its policy check behind `decide()`, keep its LLM-generated-policy mode. **Done when** its static ASR/utility on banking roughly matches the paper's.
2. Port **CaMeL** (github.com/google-research/camel-prompt-injection). CaMeL changes the pipeline (P-LLM/Q-LLM interpreter), not just the gate — add a builder that returns a different pipeline; talk to Madhav before touching `runner._pipeline`. **Done when** it runs on one suite end-to-end through `ipi run`.
3. Write the remaining static policies in `defenses/policies.yaml` (workspace, travel, slack) using only user-owned data. Record authoring time per suite.
4. Stretch: RTBAS / FIDES — check for released code first; if none, write a 1-page "what a faithful reimplementation needs" note instead of half-building it.

## Teammate 2 — Attack lane
1. Run `adaptive` (all 3 strategies) against `policy` on banking with a small limit; read every trajectory with `ipi inspect`. **Done when** you have ≥3 concrete successful payloads per strategy *or* a written reason why a strategy can't apply to that defense.
2. Replace round-robin strategy choice with a simple bandit (UCB over strategies, reward = success; update from feedback). Keep it in `attacks/adaptive.py`.
3. Add a defense-specific mode for Progent (policy-aware: read the policy from `spec()` and target allowed-but-unsafe argument values) and for CaMeL (branch steering on control-flow decisions).
4. Produce the ASR-vs-budget curve (B = 1, 3, 10, 30) on banking for `policy` and `envelope[llm]`.
   You do **not** design or change monitor rules — report weaknesses as issues for Madhav.

## Teammate 3 — Analysis lane
1. Baseline validation: confirm our no-defense numbers match AgentDojo's published ones for the chosen model (the harness swaps AgentDojo's ToolsExecutor for ours — prove it's behaviour-preserving with `none`).
2. **AgentDyn integration**: paper arXiv:2602.03117, code linked from it (github.com/leolee99/AgentDyn). Find out whether it is AgentDojo-compatible (TaskSuite format). **Done when** either a suite loads through `get_suites`-style loading in our runner, or a written adapter plan with effort estimate.
3. Plotting: `analysis/plots.py` → security–utility Pareto scatter (one point per defense), ASR-vs-budget curve, block-rule breakdown bar chart. Read only `results.csv` / `events.jsonl`.
4. Provenance-tagger precision: sample 100 `unpinned_sink` decisions from logs, hand-label whether the value really came from untrusted output. This number goes in the thesis as the tagger's known error rate.
5. Own the literature-review chapter draft (related work for every defense we evaluate).

---

## If you'd rather not split the work
Everything above is doable by one person, just slower. The genuinely parallel chunks — the ones worth handing off first if anyone is free — are **CaMeL port**, **AgentDyn integration**, and **baseline validation**: each is self-contained and doesn't block the others.
