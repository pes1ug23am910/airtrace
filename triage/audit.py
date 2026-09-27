"""A reproducible manual review sample; quotation resolution is not causal proof."""

from collections import defaultdict
import csv
import json
from pathlib import Path
import random


AUDIT_SEED = 20260927


def write_audit_sample(rows, path, seed=AUDIT_SEED):
    groups = defaultdict(list)
    for row in rows:
        if row.get("diagnosis") is not None and not row.get("excluded"):
            groups[(row["label"], row["arm"])].append(row)
    rng = random.Random(seed)
    fields = ["bundle_id", "class", "arm", "model", "view", "outcome", "diagnosis",
              "cited_quotes", "supports_diagnosis"]
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for identity in sorted(groups):
            candidates = sorted(groups[identity], key=lambda row: (row["bundle_id"], row.get("model_name") or ""))
            selected = rng.sample(candidates, min(3, len(candidates)))
            for row in selected:
                writer.writerow({
                    "bundle_id": row["bundle_id"], "class": row["label"], "arm": row["arm"],
                    "model": row.get("model_name") or "", "view": row.get("view", "client"),
                    "outcome": row.get("outcome", "DIAGNOSED"),
                    "diagnosis": json.dumps(row["diagnosis"], sort_keys=True, ensure_ascii=True),
                    "cited_quotes": json.dumps(row["diagnosis"]["evidence"], sort_keys=True, ensure_ascii=True),
                    "supports_diagnosis": "",
                })
