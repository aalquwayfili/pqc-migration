import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out"
OUT.mkdir(exist_ok=True)
DATA = json.loads((ROOT / "data/plot-data.json").read_text())
RESERVE = 8192
PAL = {
    "coder": ("#7C3AED", "#CBB2F7"),
    "q38": ("#1660D2", "#A8C6F5"),
    "q38_32": ("#06B6D4", "#9BE6F2"),
    "nemo": ("#76B900", "#CBE89A"),
    "astra": ("#101010", "#9B9B9B"),
    "fable": ("#D97757", "#F2C4B0"),
}
MARK = {"coder": "o", "q38": "s", "q38_32": "D", "nemo": "P", "astra": "^", "fable": "v"}
INK, GRID, MUTE = "#22252A", "#E9E9EC", "#8A8F98"
W_TRACE, W_LEAD = 0.5, 1.9

def apply():
    plt.rcParams.update({
        "font.size": 7, "font.family": "DejaVu Sans",
        "axes.linewidth": .6, "axes.edgecolor": INK, "axes.labelcolor": INK,
        "text.color": INK, "xtick.color": INK, "ytick.color": INK,
        "xtick.major.width": .6, "ytick.major.width": .6,
        "xtick.major.size": 2.4, "ytick.major.size": 2.4,
        "legend.frameon": False,
    })

def tidy(ax, grid_axis="both"):
    ax.grid(axis=grid_axis, color=GRID, linewidth=.55, zorder=0)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(labelsize=6.2)

def envelope(series, n):
    med, lo, hi, keep = [], [], [], []
    for i in range(n):
        v = [s[i] for s in series if len(s) > i]
        if len(v) < 5:
            continue
        keep.append(i + 1)
        med.append(np.median(v))
        lo.append(np.percentile(v, 25))
        hi.append(np.percentile(v, 75))
    return np.array(keep), np.array(med), np.array(lo), np.array(hi)

apply()
HIST_KEYS = list(DATA)

fig = plt.figure(figsize=(3.45, 3.3))
ax = fig.add_axes([.145, .135, .715, .73])
for k in HIST_KEYS:
    dark, light = PAL[k]
    rows = DATA[k]["rows"]
    if DATA[k]["native"]:
        for r in rows:
            xs = range(1, len(r["hist"]) + 1)
            ax.plot(xs, r["hist"], color=dark, linewidth=1.6,
                    marker=MARK[k], markersize=2.8, markeredgewidth=0,
                    zorder=8, solid_capstyle="round")
        continue
    for r in rows:
        ax.plot(range(1, len(r["hist"]) + 1), r["hist"], color=dark,
                linewidth=W_TRACE, alpha=.26, zorder=2)
    n = max(len(r["hist"]) for r in rows)
    x, med, lo, hi = envelope([r["hist"] for r in rows], n)
    ax.fill_between(x, lo, hi, color=light, alpha=.20, linewidth=0, zorder=3)
    ax.plot(x, med, color=dark, linewidth=W_LEAD, zorder=6, solid_capstyle="round")

ax.set_yscale("log")
ax.set_ylim(700, 300000)
for y, ls, c in ((131072, ":", INK), (32768, "--", INK), (32768 - RESERVE, "-", MUTE)):
    ax.axhline(y, color=c, linewidth=.7 if c == INK else .6, linestyle=ls, alpha=.75, zorder=5)
from matplotlib.ticker import FixedLocator, NullLocator
rax = ax.twinx()
rax.set_yscale("log"); rax.set_ylim(ax.get_ylim())
rax.yaxis.set_major_locator(FixedLocator([32768 - RESERVE, 32768, 131072]))
rax.yaxis.set_minor_locator(NullLocator())
rax.set_yticklabels(["24K", "32K", "128K"], fontsize=5.2)
rax.tick_params(length=2, pad=1.5, colors=INK)
for sp in rax.spines.values():
    sp.set_visible(False)
ax.set_yticks([1000, 10000, 100000]); ax.set_yticklabels(["1K", "10K", "100K"])
ax.set_xlim(0, 62)
ax.set_xlabel("model requests", labelpad=2.5)
ax.set_ylabel("prompt tokens", labelpad=2.5)
tidy(ax)

h = [Line2D([], [], color=PAL[k][0], linewidth=W_LEAD,
            label=f"{DATA[k]['label']}, {DATA[k]['ctx']//1024}K")
     for k in HIST_KEYS if not DATA[k]["native"]]
h += [Line2D([], [], color=PAL[k][0], linewidth=1.6,
             marker=MARK[k], markersize=2.8, markeredgewidth=0,
             label=DATA[k]["label"])
      for k in HIST_KEYS if DATA[k]["native"]]
h += [Line2D([], [], color=MUTE, marker="o", linestyle="none", markersize=2.8,
             markerfacecolor="white", markeredgewidth=.7, label="submitted, failed"),
      Line2D([], [], color=MUTE, marker="s", linestyle="none", markersize=2.8,
             markerfacecolor="white", markeredgewidth=.75, label="unparseable reply"),
      Line2D([], [], color=MUTE, marker="x", linestyle="none", markersize=4.0,
             markeredgewidth=1.0, label="context exceeded"),
      Line2D([], [], color=MUTE, marker="D", linestyle="none", markersize=2.8,
             markerfacecolor="white", markeredgewidth=.75, label="60 requests used"),
      Line2D([], [], color=MUTE, marker="*", linestyle="none", markersize=7,
             markeredgecolor="white", markeredgewidth=.5, label="all checks passed")]
fig.legend(handles=h, loc="upper center", bbox_to_anchor=(.55, 1.004), ncol=3,
           fontsize=5.0, handlelength=1.7, columnspacing=1.0, handletextpad=.5,
           labelspacing=.35)
ins = fig.add_axes([.545, .185, .305, .245])
for k in HIST_KEYS:
    dark, light = PAL[k]
    rows = DATA[k]["rows"]
    if DATA[k]["native"]:
        for r in rows:
            ins.plot(range(1, len(r["hist"]) + 1), r["hist"], color=dark, linewidth=1.3,
                     marker=MARK[k], markersize=2.2, markeredgewidth=0, zorder=8)
        continue
    n = max(len(r["hist"]) for r in rows)
    x, med, lo, hi = envelope([r["hist"] for r in rows], n)
    ins.fill_between(x, lo, hi, color=light, alpha=.22, linewidth=0, zorder=3)
    ins.plot(x, med, color=dark, linewidth=1.3, zorder=6)
stop_markers = {
    "Submitted": ("o", 2.4),
    "ContextWindowExceededError": ("x", 3.5),
    "RepeatedFormatError": ("s", 2.4),
    "LimitsExceeded": ("D", 2.4),
}
full_pass_counts = {}
grouped_counts = {}
for k in HIST_KEYS:
    full_pass_counts[k] = 0
    dark = PAL[k][0]
    groups = {}
    for r in DATA[k]["rows"]:
        passed = r["full"]
        full_pass_counts[k] += int(passed)
        outcome = "pass" if passed else r["stop"]
        key = (outcome, 60) if len(r["hist"]) == 60 else (outcome, r["name"])
        groups.setdefault(key, []).append(r)
    for group in groups.values():
        r = group[0]
        passed = r["full"]
        marker, size = ("*", 5.5) if passed else stop_markers[r["stop"]]
        x = len(r["hist"])
        ends = [row["hist"][-1] for row in group]
        y = float(np.median(ends))
        if len(group) > 1:
            grouped_counts[(k, "pass" if passed else r["stop"], x)] = len(group)
            ax.vlines(x, min(ends), max(ends), color=dark, linewidth=.6, alpha=.5, zorder=6)
        for axis, scale in ((ax, 1.0), (ins, .8)):
            if axis is ins and not passed:
                continue
            axis.plot(x, y, linestyle="none",
                      marker=marker, markersize=size * scale, color=dark,
                      markerfacecolor=dark if passed else "white",
                      markeredgecolor="white" if passed else dark,
                      markeredgewidth=.45 if passed else .65,
                      alpha=1.0 if passed else .75,
                      zorder=10 if passed else 7)
assert full_pass_counts == {"coder": 0, "q38": 36, "q38_32": 4, "nemo": 0, "astra": 2, "fable": 2}
assert grouped_counts == {("q38", "pass", 60): 11, ("nemo", "LimitsExceeded", 60): 28}
print("successful attempts represented:", full_pass_counts)
print("grouped endpoints:", grouped_counts)

ins.axhline(32768 - RESERVE, color=MUTE, linewidth=.5, zorder=4)
ins.set_xlim(1, 24)
ins.set_ylim(0, 45000)
ins.set_yticks([0, 20000, 40000])
ins.set_yticklabels(["0", "20K", "40K"], fontsize=4.8)
ins.set_xticks([1, 10, 20])
ins.tick_params(labelsize=4.8, length=1.6, pad=1.2)
ins.grid(color=GRID, linewidth=.45, zorder=0)
ins.set_axisbelow(True)
for sp in ins.spines.values():
    sp.set_linewidth(.5); sp.set_color(MUTE)
ins.set_title("first 24 requests, linear scale", fontsize=4.8, color=MUTE, pad=1.6)

fig.savefig(OUT / "context.png", dpi=400)
fig.savefig(OUT / "context.pdf")
plt.close(fig)
