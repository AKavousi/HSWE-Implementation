from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "results" / "message_length_times.csv"
OUTPUT_PATH = ROOT / "results" / "hswe_enc_dec_message_lengths.png"

df = pd.read_csv(CSV_PATH)

plt.style.use("default")

fig, ax = plt.subplots(figsize=(7.6, 4.4), dpi=300)
fig.patch.set_facecolor("white")
ax.set_facecolor("white")

ax.plot(
    df["message_bits"],
    df["encryption_mean_ms"],
    color="#35a7e8",
    marker="X",
    markersize=7,
    linewidth=2.2,
    label="Encryption",
)

ax.plot(
    df["message_bits"],
    df["decryption_mean_ms"],
    color="#ff7f0e",
    marker="o",
    markersize=5.5,
    linewidth=2.2,
    label="Decryption",
)

ax.set_title("HSWE-BLS Encryption and Decryption Time", fontsize=13, pad=14)
ax.set_xlabel("Message length (bits)")
ax.set_ylabel("Mean time (ms)")

ax.set_xlim(-0.3, 16.3)
ax.set_xticks(range(17))

y_min = min(df["encryption_mean_ms"].min(), df["decryption_mean_ms"].min())
y_max = max(df["encryption_mean_ms"].max(), df["decryption_mean_ms"].max())
padding = 0.08 * (y_max - y_min)

ax.set_ylim(y_min - padding, y_max + padding)

ax.grid(True, axis="y", color="#b0b0b0", alpha=0.35, linewidth=0.8)
ax.grid(False, axis="x")

for spine in ax.spines.values():
    spine.set_color("black")
    spine.set_linewidth(1.0)

ax.tick_params(colors="black")

ax.legend(
    loc="upper center",
    bbox_to_anchor=(0.5, 1.01),
    ncol=2,
    frameon=False,
)

fig.tight_layout()

fig.savefig(
    OUTPUT_PATH,
    dpi=300,
    bbox_inches="tight",
    facecolor="white",
    edgecolor="white",
)

print(f"Saved plot to: {OUTPUT_PATH}")
plt.show()