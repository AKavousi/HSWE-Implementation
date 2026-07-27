from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "results" / "private_tally_times.csv"
OUTPUT_PATH = ROOT / "results" / "private_tally_benchmark.png"

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

# (a) End-to-end private tally cost
ax = axes[0]

ax.plot(
    df["batch_size"],
    df["total_ms"],
    color="#35a7e8",
    marker="X",
    markersize=7,
    linewidth=2.2,
    label="Private tally total",
)

ax.plot(
    df["batch_size"],
    df["decrypt_ms"],
    color="#ff7f0e",
    marker="o",
    markersize=5,
    linewidth=2.0,
    label="Final aggregate decrypt",
)

ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xticks(df["batch_size"])
ax.set_xticklabels(df["batch_size"])

ax.set_title("Private HSWE-BLS tally", color="#eeeeee", fontsize=13)
ax.set_xlabel("# Ciphertexts", color="#eeeeee")
ax.set_ylabel("Time (ms)", color="#eeeeee")

ax.legend(
    loc="upper left",
    frameon=True,
    facecolor="#303030",
    edgecolor="#777777",
    labelcolor="#eeeeee",
)

# (b) Cost breakdown
ax = axes[1]

ax.plot(
    df["batch_size"],
    df["blind_each_ms"],
    color="#35a7e8",
    marker="X",
    markersize=7,
    linewidth=2.2,
    label="Blind + share",
)

ax.plot(
    df["batch_size"],
    df["aggregate_ms"],
    color="#a78bfa",
    marker="s",
    markersize=5,
    linewidth=2.0,
    label="Aggregate",
)

ax.plot(
    df["batch_size"],
    df["reconstruct_ms"],
    color="#facc15",
    marker="^",
    markersize=5,
    linewidth=2.0,
    label="Reconstruct blind",
)

ax.plot(
    df["batch_size"],
    df["unblind_ms"],
    color="#22c55e",
    marker="D",
    markersize=5,
    linewidth=2.0,
    label="Unblind aggregate",
)

ax.plot(
    df["batch_size"],
    df["decrypt_ms"],
    color="#ff7f0e",
    marker="o",
    markersize=5,
    linewidth=2.0,
    label="Decrypt aggregate",
)

ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xticks(df["batch_size"])
ax.set_xticklabels(df["batch_size"])

ax.set_title("Privacy-wrapper cost breakdown", color="#eeeeee", fontsize=13)
ax.set_xlabel("# Ciphertexts", color="#eeeeee")
ax.set_ylabel("Time (ms)", color="#eeeeee")

ax.legend(
    loc="upper left",
    frameon=True,
    facecolor="#303030",
    edgecolor="#777777",
    labelcolor="#eeeeee",
    fontsize=8.5,
)

fig.text(
    0.25,
    0.01,
    "(a) Private aggregate-tally latency",
    ha="center",
    color="#eeeeee",
    fontsize=11,
)

fig.text(
    0.75,
    0.01,
    "(b) Stateful privacy-wrapper overhead",
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