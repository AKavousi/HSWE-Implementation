import csv
from collections import defaultdict

import matplotlib.pyplot as plt

rows = []

with open("lattice_binary_results.csv", newline="", encoding="utf-8") as file:
    for row in csv.DictReader(file):
        row["batch_size"] = int(row["batch_size"])
        row["median_us"] = float(row["median_us"])
        row["lower_us"] = float(row["lower_us"])
        row["upper_us"] = float(row["upper_us"])
        rows.append(row)

groups = {
    "lattice_binary_aggregate": "Aggregate XOR",
    "lattice_binary_aggregate_decrypt": "Aggregate decrypt",
    "lattice_binary_naive_decrypt": "Naive decrypt",
}

series = defaultdict(list)

for row in rows:
    if row["group"] in groups:
        series[row["group"]].append(row)

missing = [group for group in groups if not series[group]]
if missing:
    raise SystemExit(f"Missing benchmark data for: {', '.join(missing)}")

plt.figure(figsize=(10, 6))

for group, label in groups.items():
    values = sorted(series[group], key=lambda row: row["batch_size"])

    x = [row["batch_size"] for row in values]
    y = [row["median_us"] for row in values]
    lower_error = [row["median_us"] - row["lower_us"] for row in values]
    upper_error = [row["upper_us"] - row["median_us"] for row in values]

    plt.errorbar(
        x,
        y,
        yerr=[lower_error, upper_error],
        marker="o",
        capsize=4,
        linewidth=2,
        label=label,
    )

plt.xscale("log", base=2)
plt.yscale("log")
plt.xticks([1, 8, 32, 128, 512], ["1", "8", "32", "128", "512"])
plt.xlabel("Batch size")
plt.ylabel("Median time (microseconds)")
plt.title("Lattice Binary Benchmark Scaling")
plt.grid(True, which="both", linestyle="--", alpha=0.35)
plt.legend()
plt.tight_layout()
plt.savefig("lattice_binary_scaling.png", dpi=200)

print("Wrote lattice_binary_scaling.png")
