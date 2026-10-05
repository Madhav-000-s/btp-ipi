"""CLI.

  ipi run configs/smoke_oracle.yaml [--workers 8]
  ipi metrics results/smoke_oracle
  ipi inspect results/smoke_oracle --user-task user_task_0 --injection-task injection_task_1
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ipi import metrics
from ipi.runner import Runner, load_config


def main():
    ap = argparse.ArgumentParser(prog="ipi")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("config")
    r.add_argument("--workers", type=int)
    m = sub.add_parser("metrics")
    m.add_argument("path")
    i = sub.add_parser("inspect", help="print the gated calls of matching episodes")
    i.add_argument("path")
    i.add_argument("--user-task")
    i.add_argument("--injection-task")
    i.add_argument("--defense")
    a = ap.parse_args()

    if a.cmd == "run":
        Runner(load_config(a.config)).run(a.workers)
        metrics.main([str(Path(load_config(a.config).get("out_dir", "results")) / load_config(a.config)["run_name"])])
    elif a.cmd == "metrics":
        metrics.main([a.path])
    elif a.cmd == "inspect":
        for line in open(Path(a.path) / "events.jsonl"):
            e = json.loads(line)
            if e["event"] not in ("tool_call", "defense_reset", "episode_end"):
                continue
            if a.user_task and e["user_task"] != a.user_task:
                continue
            if a.injection_task and e["injection_task"] != a.injection_task:
                continue
            if a.defense and a.defense not in e["defense"]:
                continue
            if e["event"] == "tool_call":
                print(f"  [{e['defense']}|a{e['attempt']}] {e['verdict']:>8} {e['function']}({json.dumps(e['args'])[:120]}) "
                      f"{('- ' + e['reason']) if e['reason'] else ''}")
            elif e["event"] == "defense_reset" and e.get("state"):
                print(f"[{e['user_task']}/{e['injection_task']}] state: {json.dumps(e['state'])[:400]}")
            else:
                print(f"  => utility={e['utility']} attack_success={e['attack_success']}\n")


if __name__ == "__main__":
    main()
