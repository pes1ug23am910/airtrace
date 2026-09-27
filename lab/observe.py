"""Describe the dev captures without assuming class-specific signatures."""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import subprocess

from lab.manifest import verify_manifest
from triage.data import load_bundle


def observations(dataset: Path, binary=None) -> list[dict]:
    manifest = verify_manifest(dataset)
    groups = defaultdict(list)
    for entry in manifest["bundles"]:
        if entry["split"] != "dev":
            continue
        path = Path(dataset) / entry["path"]
        meta = json.loads((path / "meta.json").read_text(encoding="utf-8"))
        try:
            bundle = load_bundle(path, binary=binary)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            groups[meta["label"]].append({
                "id": entry["id"], "run_status": meta["status"], "quarantined": entry["quarantined"], "read_error": str(error),
                "status_codes": [], "reason_codes": [], "four_messages_observed": False,
                "lease_logged": False, "parser_returncode": None, "log_status_reason_lines": [],
            })
            continue
        frames = list(bundle.frames.values())
        statuses = sorted({frame["status_code"] for frame in frames if frame.get("status_code") is not None})
        reasons = sorted({frame["reason_code"] for frame in frames if frame.get("reason_code") is not None})
        groups[meta["label"]].append({
            "id": entry["id"], "run_status": bundle.meta["status"], "quarantined": entry["quarantined"], "read_error": None,
            "status_codes": statuses, "reason_codes": reasons,
            "four_messages_observed": "complete=yes" in bundle.stats,
            "lease_logged": any(re.search(r"\b(?:bound to\s+\d+\.\d+\.\d+\.\d+|lease of\s+\d+\.\d+\.\d+\.\d+.*obtained)", line, re.IGNORECASE)
                                for line in bundle.logs["dhcp_client"]),
            "parser_returncode": bundle.returncode,
            "log_status_reason_lines": [
                f"{source}:{number}: {line}"
                for source, lines in bundle.logs.items()
                for number, line in enumerate(lines, 1)
                if re.search(r"\b(?:status|reason)(?:_code)?[= :]+\d+", line, re.IGNORECASE)
            ],
        })
    return [{"label": label, "runs": groups[label]} for label in sorted(groups)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--binary")
    args = parser.parse_args()
    print("Dev observations only. Four messages observed is not proof of one valid handshake.")
    print("| Class | Bundles | Failed runs | Quarantined | Read errors | Status codes | Reason codes | Four messages | Lease logged |")
    print("| --- | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: |")
    for group in observations(args.dataset, args.binary):
        rows = group["runs"]
        statuses = sorted({code for row in rows for code in row["status_codes"]})
        reasons = sorted({code for row in rows for code in row["reason_codes"]})
        readable = sum(row["read_error"] is None for row in rows)
        print(f"| {group['label']} | {len(rows)} | {sum(row['run_status'] == 'failed' for row in rows)} "
              f"| {sum(row['quarantined'] for row in rows)} | {len(rows) - readable} | {statuses} | {reasons} "
              f"| {sum(row['four_messages_observed'] for row in rows)}/{readable} "
              f"| {sum(row['lease_logged'] for row in rows)}/{readable} |")
        for row in rows:
            if row["read_error"]:
                print(f"    {row['id']}: READ ERROR: {row['read_error']}")
            for line in row["log_status_reason_lines"]:
                print(f"    {row['id']}: {line}")


if __name__ == "__main__":
    main()
