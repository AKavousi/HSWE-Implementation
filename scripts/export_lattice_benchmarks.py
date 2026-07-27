import csv
import json
from pathlib import Path

root = Path("target/criterion")
output = Path("lattice_binary_results.csv")
rows = []

for estimates_path in root.rglob("new/estimates.json"):
    parts = estimates_path.relative_to(root).parts

    if len(parts) < 3 or not parts[0].startswith("lattice_binary_"):
        continue

    group = parts[0]
    parameter = parts[1] if len(parts) >= 4 else "one_bit"

    with estimates_path.open(encoding="utf-8") as file:
        estimates = json.load(file)

    median = estimates["median"]
    interval = median["confidence_interval"]

    rows.append({
        "group": group,
        "batch_size": 1 if parameter == "one_bit" else int(parameter),
        "median_ns": median["point_estimate"],
        "lower_ns": interval["lower_bound"],
        "upper_ns": interval["upper_bound"],
        "median_us": median["point_estimate"] / 1_000,
        "lower_us": interval["lower_bound"] / 1_000,
        "upper_us": interval["upper_bound"] / 1_000,
    })

if not rows:
    raise SystemExit(
        "No Criterion estimates found. Run cargo bench first."
    )

rows.sort(key=lambda row: (row["group"], row["batch_size"]))

with output.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows to {output.resolve()}")
