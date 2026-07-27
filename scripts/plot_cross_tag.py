from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "results" / "cross_tag_times.csv"
OUTPUT_PATH = ROOT / "results" / "cross_tag_benchmark.png"

df = pd.read_csv(CSV_PATH)

plt.style.use("dark_background")

fig, axes = plt.subplots(1, 2, figsize=(13, 5.2), dpi=200)
fig.patch.set_facecolor("#222222")

for ax in axes:
    ax.set_facecolor("#222222")
    ax.grid(True, which="both", alpha=0.20, linewidth=0.8)
    ax.tick_params(colors="#dddddd")

    for spine in ax.spines.values():
        spine.set_color("#bbbbbb")
        spine.set_linewidth(1.0)

# (a) Cross-tag extraction vs sequential decryption
ax = axes[0]

ax.plot(
    df["tag_count"],
    df["cross_tag_decrypt_ms"],
    color="#35a7e8",
    marker="X",
    markersize=7,
    linewidth=2.2,
    label="Cross-tag decrypt",
)

ax.plot(
    df["tag_count"],
    df["naive_decrypt_ms"],
    color="#ff7f0e",
    marker="o",
    markersize=5,
    linewidth=2.0,
    linestyle="--",
    label="Naïve decrypt",
)

ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xticks(df["tag_count"])
ax.set_xticklabels(df["tag_count"])

ax.set_title("Cross-tag decryption cost", color="#eeeeee", fontsize=13)
ax.set_xlabel("# Distinct tags", color="#eeeeee")
ax.set_ylabel("Time (ms)", color="#eeeeee")

ax.legend(
    loc="upper left",
    frameon=True,
    facecolor="#303030",
    edgecolor="#777777",
    labelcolor="#eeeeee",
)

# (b) Aggregation cost
ax = axes[1]

ax.plot(
    df["tag_count"],
    df["aggregate_ms"],
    color="#a78bfa",
    marker="s",
    markersize=6,
    linewidth=2.2,
    label="Cross-tag aggregate",
)

ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xticks(df["tag_count"])
ax.set_xticklabels(df["tag_count"])

ax.set_title("Cross-tag aggregation cost", color="#eeeeee", fontsize=13)
ax.set_xlabel("# Distinct tags", color="#eeeeee")
ax.set_ylabel("Time (ms)", color="#eeeeee")

ax.legend(
    loc="upper left",
    frameon=True,
    facecolor="#303030",
    edgecolor="#777777",
    labelcolor="#eeeeee",
)

fig.text(
    0.25,
    0.01,
    "(a) Linear cross-tag extraction",
    ha="center",
    color="#eeeeee",
    fontsize=11,
)

fig.text(
    0.75,
    0.01,
    "(b) Homomorphic aggregation",
    ha="center",
    color="#eeeeee",
    fontsize=11,
)

fig.tight_layout(rect=(0, 0.05, 1, 1))

fig.savefig(
    OUTPUT_PATH,
    dpi=300,
    bbox_inches="tight",
    facecolor=fig.get_facecolor(),
)

print(f"Saved plot to: {OUTPUT_PATH}")
plt.show()