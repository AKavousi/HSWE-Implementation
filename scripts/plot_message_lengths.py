from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "results" / "message_length_times.csv"
OUTPUT_PATH = ROOT / "results" / "hswe_enc_dec_message_lengths.png"

df = pd.read_csv(CSV_PATH)

plt.style.use("dark_background")

fig, ax = plt.subplots(figsize=(7.2, 5.2), dpi=200)
fig.patch.set_facecolor("#222222")
ax.set_facecolor("#222222")

ax.plot(
    df["message_bits"],
    df["encryption_mean_ms"],
    color="#35a7e8",
    marker="X",
    markersize=6,
    linewidth=2.1,
    label="Encryption",
)

ax.plot(
    df["message_bits"],
    df["decryption_mean_ms"],
    color="#ff7f0e",
    marker="o",
    markersize=5,
    linewidth=2.1,
    label="Decryption",
)

ax.set_title("HSWE-BLS", color="#eeeeee", fontsize=13, pad=10)
ax.set_xlabel("Message bit length", color="#eeeeee")
ax.set_ylabel("Time (ms)", color="#eeeeee")

ax.set_xlim(-0.3, 16.3)
ax.set_xticks(range(17))

# Keeps the two lines visually comparable without excessive empty space.
ax.set_ylim(2.9, 4.0)

ax.grid(True, alpha=0.20, linewidth=0.8)
ax.tick_params(colors="#dddddd")

for spine in ax.spines.values():
    spine.set_color("#bbbbbb")
    spine.set_linewidth(1.0)

ax.legend(
    loc="center right",
    frameon=True,
    facecolor="#303030",
    edgecolor="#777777",
    labelcolor="#eeeeee",
)

fig.text(
    0.5,
    0.01,
    "(a) HSWE-BLS Enc(·), Dec(·) times",
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