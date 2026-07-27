from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
df = pd.read_csv(ROOT / "benchmark_results.csv")

plt.style.use("dark_background")
fig, axes = plt.subplots(1, 2, figsize=(12, 5), dpi=180)
fig.patch.set_facecolor("#222222")

for ax in axes:
    ax.set_facecolor("#222222")
    ax.grid(True, which="both", alpha=0.22)
    ax.tick_params(colors="#dddddd")
    for spine in ax.spines.values():
        spine.set_color("#bbbbbb")

# (a) Aggregate vs naïve decryption
axes[0].plot(
    df["batch_size"],
    df["aggregate_decryption_ms"],
    marker="o",
    linewidth=2.2,
    color="#ff7f0e",
    label="Aggregate decryption",
)
axes[0].plot(
    df["batch_size"],
    df["naive_decryption_ms"],
    marker="o",
    linewidth=2.2,
    color="#35a7e8",
    label="Naïve decryption",
)
axes[0].set_xscale("log", base=2)
axes[0].set_yscale("log")
axes[0].set_xticks(df["batch_size"])
axes[0].set_xticklabels(df["batch_size"])
axes[0].set_title("HSWE-BLS", color="#eeeeee")
axes[0].set_xlabel("# Ciphertexts")
axes[0].set_ylabel("Time (ms)")
axes[0].legend(frameon=True, facecolor="#333333", edgecolor="#777777")

# (b) Homomorphic addition
axes[1].plot(
    df["batch_size"],
    df["aggregation_ms"],
    marker="X",
    markersize=7,
    linewidth=2.2,
    color="#35a7e8",
    label="HSWE-BLS",
)
axes[1].set_xscale("log", base=2)
axes[1].set_yscale("log")
axes[1].set_xticks(df["batch_size"])
axes[1].set_xticklabels(df["batch_size"])
axes[1].set_title("Homomorphic Addition", color="#eeeeee")
axes[1].set_xlabel("# Ciphertexts")
axes[1].set_ylabel("Time (ms)")
axes[1].legend(frameon=True, facecolor="#333333", edgecolor="#777777")

fig.text(0.25, 0.01, "(a) HSWE-BLS decryption scaling", ha="center", fontsize=11)
fig.text(0.75, 0.01, "(b) Homomorphic addition efficiency", ha="center", fontsize=11)

fig.tight_layout(rect=(0, 0.05, 1, 1))
fig.savefig(ROOT / "hswe_benchmark_figure.png", facecolor=fig.get_facecolor())
plt.show()