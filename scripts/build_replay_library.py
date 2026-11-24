"""Harvest the payloads the LLM attacker actually wrote in earlier hijacked-mode runs into a replay library.

Why: the attacker model declined most of its attempts, and the harness injected the refusal text as a payload
(docs/results.md, section 0). The defenses therefore faced different numbers of real attacks. The replay attack
(ipi.attacks.replay) plays the SAME real payloads against every defense.

One line per (suite, user_task, injection_task) with its payloads, strongest first:
  1. payloads that reached the attacker's goal against some defense,
  2. payloads that got a goal tool executed,
  3. the rest, interleaved across the defenses they were written against.
Refusals and unparsed attacker output are dropped. Injections are stored as they were injected (already escaped
for the suite's YAML), so a replay is byte-identical to the original attempt.

    python scripts/build_replay_library.py results/run_a results/run_b ... -o data/replay_payloads.jsonl
"""
import argparse
import collections
import itertools
import json
import re
from pathlib import Path

REFUSAL = re.compile(r"i won'?t|i will not|i can'?t (write|help)|i cannot (write|help)|not going to write|i decline|"
                     r"won't (write|produce|revise|provide)|refus", re.I)


def harvest(run_dir: Path, goal_tools: dict):
    open_ep, out = {}, []
    for line in open(run_dir / "events.jsonl", encoding="utf-8"):
        if '"adaptive' not in line:
            continue
        r = json.loads(line)
        if r.get("attempt", 0) == 0 or not r.get("injection_task"):
            continue  # attempt 0 is the static seed
        k = (r["defense"], r["user_task"], r["injection_task"], r["repeat"], r["attempt"])
        if r["event"] == "episode_start":
            open_ep[k] = {"suite": r["suite"], "user_task": r["user_task"], "injection_task": r["injection_task"],
                          "injections": r["injections"], "defense": r["defense"], "run": run_dir.name,
                          "strategy": (r.get("attack_meta") or {}).get("strategy"), "executed": []}
        elif r["event"] == "tool_call" and k in open_ep and r.get("executed"):
            open_ep[k]["executed"].append(r["function"])
        elif r["event"] == "episode_end" and k in open_ep:
            e = open_ep.pop(k)
            e["success"] = bool(r.get("attack_success"))
            out.append(e)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("-o", "--out", default="data/replay_payloads.jsonl")
    ap.add_argument("--max-per-pair", type=int, default=20)
    a = ap.parse_args()

    from agentdojo.task_suite.load_suites import get_suites
    suites = get_suites("v1.2.2")
    goal_tools = {}
    stats = collections.Counter()
    pairs = collections.defaultdict(dict)  # pair -> {text: entry}
    for run in a.runs:
        for e in harvest(Path(run), goal_tools):
            stats["attempts"] += 1
            text = next(iter(e["injections"].values()), "")
            if REFUSAL.search(text):
                stats["refusal"] += 1
                continue
            if text.lstrip().startswith("{") or len(text.strip()) < 20:
                stats["unparsed"] += 1
                continue
            s = suites[e["suite"]]
            gk = (e["suite"], e["injection_task"])
            if gk not in goal_tools:
                it = s.get_injection_task_by_id(e["injection_task"])
                env = s.load_and_inject_default_environment({})
                goal_tools[gk] = {c.function for c in it.ground_truth(env)}
            e["goal_tool_executed"] = bool(goal_tools[gk] & set(e.pop("executed")))
            pk = (e["suite"], e["user_task"], e["injection_task"])
            old = pairs[pk].get(text)
            if old is None:
                e["sources"] = [e.pop("defense")]
                pairs[pk][text] = e
            else:  # same payload seen again: keep its best outcome
                stats["duplicate"] += 1
                old["success"] |= e["success"]
                old["goal_tool_executed"] |= e["goal_tool_executed"]
                if e["defense"] not in old["sources"]:
                    old["sources"].append(e["defense"])

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    sizes = []
    with open(a.out, "w", encoding="utf-8") as f:
        for pk in sorted(pairs):
            es = list(pairs[pk].values())
            tier = lambda e: 0 if e["success"] else 1 if e["goal_tool_executed"] else 2
            ordered = []
            for t in (0, 1, 2):
                by_src = collections.defaultdict(list)
                for e in es:
                    if tier(e) == t:
                        by_src[e["sources"][0]].append(e)
                rows = itertools.zip_longest(*(by_src[k] for k in sorted(by_src)))
                ordered += [e for row in rows for e in row if e is not None]
            ordered = ordered[: a.max_per_pair]
            sizes.append(len(ordered))
            f.write(json.dumps({"suite": pk[0], "user_task": pk[1], "injection_task": pk[2], "payloads": [
                {"injections": e["injections"], "sources": e["sources"], "run": e["run"], "strategy": e["strategy"],
                 "succeeded_before": e["success"], "goal_tool_executed": e["goal_tool_executed"]} for e in ordered]},
                ensure_ascii=False) + "\n")
    print(dict(stats))
    print(f"{len(sizes)} pairs, payloads per pair: min {min(sizes)}, median {sorted(sizes)[len(sizes)//2]}, max {max(sizes)}")
    for n in (1, 3, 5, 9):
        print(f"  pairs with >= {n} payloads: {sum(s >= n for s in sizes)}")


if __name__ == "__main__":
    main()
