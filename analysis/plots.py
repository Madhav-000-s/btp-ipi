"""Thesis plots from results.csv only.  python analysis/plots.py results/<run> [--out figs]
  pareto.png        benign utility vs ASR, one point per defense (static attack)
  asr_budget.png    adaptive ASR@B for B=1..budget (from attempts-to-first-success)
  block_rules.png   which monitor/policy rule fired, per defense
"""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run"); ap.add_argument("--out", default=None); ap.add_argument("--static", default="important_instructions")
    a = ap.parse_args()
    df = pd.read_csv(Path(a.run) / "results.csv", keep_default_na=False)
    out = Path(a.out or Path(a.run) / "figs"); out.mkdir(parents=True, exist_ok=True)
    ben, att = df[df.injection_task == ""], df[df.injection_task != ""]

    st = att[att.attack == a.static].groupby("defense").attack_success.mean() * 100
    ut = ben.groupby("defense").utility.mean() * 100
    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    for d in st.index:
        ax.scatter(st[d], ut.get(d, float("nan")), s=60); ax.annotate(d, (st[d], ut.get(d, 0)), fontsize=8, xytext=(4, 4), textcoords="offset points")
    ax.set_xlabel(f"ASR % ({a.static})"); ax.set_ylabel("Benign utility %"); ax.set_title("Security-utility trade-off")
    ax.set_xlim(-3, 103); ax.set_ylim(-3, 103); ax.grid(alpha=.3); fig.tight_layout(); fig.savefig(out / "pareto.png", dpi=160)

    ad = att[att.attack.str.startswith("adaptive")]
    if not ad.empty:
        fig, ax = plt.subplots(figsize=(6.4, 4.2)); B = int(ad.attempts.max())
        for d, g in ad.groupby("defense"):
            ax.plot(range(1, B + 1), [100 * ((g.attack_success == 1) & (g.attempts <= b)).mean() for b in range(1, B + 1)], marker="o", label=d)
        ax.set_xlabel("Attacker budget B"); ax.set_ylabel("ASR@B %"); ax.set_title("Adaptive ASR vs budget"); ax.grid(alpha=.3); ax.legend(fontsize=7)
        fig.tight_layout(); fig.savefig(out / "asr_budget.png", dpi=160)

    r = att.assign(rule=att.block_rules.str.split("|")).explode("rule")
    r = r[r.rule != ""].groupby(["defense", "rule"]).size().unstack(fill_value=0)
    if not r.empty:
        ax = r.plot.barh(stacked=True, figsize=(7, 4.2)); ax.set_xlabel("episodes in which rule fired"); ax.set_title("Block / escalate rules")
        plt.tight_layout(); plt.savefig(out / "block_rules.png", dpi=160)
    print("figures ->", out)


if __name__ == "__main__":
    main()
