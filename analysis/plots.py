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

    # Security axis: the static attack if present, else whatever single attack the run has (e.g. replay).
    atk = a.static if (att.attack == a.static).any() else (att.attack.iloc[0] if not att.empty else a.static)
    st = att[att.attack == atk].groupby("defense").attack_success.mean() * 100
    # Benign utility if the run has benign episodes; replay runs have none, so fall back to utility-under-attack.
    ut = (ben.groupby("defense").utility.mean() * 100) if not ben.empty else (att[att.attack == atk].groupby("defense").utility.mean() * 100)
    ylab = "Benign utility %" if not ben.empty else "Utility under attack %"
    fig, ax = plt.subplots(figsize=(7.2, 5.0))
    # de-overlap labels: nudge each annotation vertically when points share an (x, y) neighbourhood
    placed = []
    for d in sorted(st.index, key=lambda d: (st[d], ut.get(d, 0))):
        x, y = st[d], ut.get(d, float("nan"))
        ax.scatter(x, y, s=70, zorder=3)
        dy = 6
        while any(abs(x - px) < 9 and abs((y + dy) - py) < 5 for px, py in placed):
            dy += 11
        ax.annotate(d, (x, y), fontsize=8, xytext=(6, dy), textcoords="offset points",
                    arrowprops=dict(arrowstyle="-", lw=.4, color="grey") if dy > 6 else None)
        placed.append((x, y + dy))
    ax.set_xlabel(f"ASR % ({atk})"); ax.set_ylabel(ylab); ax.set_title("Security-utility trade-off")
    ax.set_xlim(-4, max(103, st.max() + 6)); ax.set_ylim(-3, 103); ax.grid(alpha=.3); fig.tight_layout(); fig.savefig(out / "pareto.png", dpi=160)

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
