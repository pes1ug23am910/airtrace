"""Describe dev evidence and recorded outcomes without assuming fault signatures."""

import argparse
from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import re
from statistics import median
import subprocess

from lab.manifest import verify_manifest
from lab.outcomes import observed_summary
from triage.data import load_bundle


DIRECTIONS = ("ap_to_station", "station_to_ap", "ap_to_broadcast", "other")
EVENTS = ("auth", "assoc", "eapol", "dhcp")
DHCP_EVENT = re.compile(
    r"\b(?:DHCP(?:DISCOVER|OFFER|REQUEST|ACK|NAK|DECLINE|RELEASE|INFORM)"
    r"|(?:sending|broadcasting) (?:discover|select|request)|lease of|bound to)\b",
    re.IGNORECASE,
)
LEASE = re.compile(
    r"\b(?:bound to\s+\d+\.\d+\.\d+\.\d+|lease of\s+\d+\.\d+\.\d+\.\d+.*obtained)",
    re.IGNORECASE,
)


def reason_direction(frame: dict, parameters: dict) -> str:
    """Management addr1 is receiver and addr2 is transmitter; keep other peers separate."""
    addresses = [address.lower() for address in frame.get("addrs", [])]
    ap = parameters.get("ap_mac", "").lower()
    station = parameters.get("station_mac", "").lower()
    if len(addresses) < 2 or not ap or not station:
        return "other"
    receiver, transmitter = addresses[:2]
    if transmitter == ap and receiver == station:
        return "ap_to_station"
    if transmitter == station and receiver == ap:
        return "station_to_ap"
    if transmitter == ap and receiver == "ff:ff:ff:ff:ff:ff":
        return "ap_to_broadcast"
    return "other"


def first_events(bundle) -> dict:
    """Elapsed event times, not completion times; missing origin/receipts stay unknown.

    Capture events use pcap wall time relative to the tested station's start.
    EAPOL is limited to classified Key messages 1-4: the CLI does not expose
    arbitrary EAPOL events such as EAPOL-Start.
    DHCP uses the first protocol-event line in the tested client's log and its
    monotonic receipt time. Pipe buffering can delay that receipt. No packet-level
    DHCP claim is possible from the current parser's frame fields.
    """
    meta = bundle.meta
    values = dict.fromkeys(EVENTS)
    start = meta.get("scenario_started_at")
    start_wall = datetime.fromisoformat(start.replace("Z", "+00:00")).timestamp() if start else None
    start_mono = meta.get("scenario_started_monotonic_ns")
    receipts = (meta.get("observation_window") or {}).get("logs", {}).get("dhcp_client", {}).get("lines")
    available = {"capture": start_wall is not None,
                 "dhcp": start_mono is not None and receipts is not None}
    if available["capture"]:
        for frame in bundle.frames.values():
            if reason_direction(frame, meta["parameters"]) not in ("ap_to_station", "station_to_ap"):
                continue
            timestamp = frame.get("ts")
            if not isinstance(timestamp, (int, float)) or timestamp < start_wall:
                continue
            event = None
            if frame.get("type_id") == 0 and frame.get("subtype_id") == 11:
                event = "auth"
            elif frame.get("type_id") == 0 and frame.get("subtype_id") in (0, 1, 2, 3):
                event = "assoc"
            elif frame.get("eapol_msg") in (1, 2, 3, 4):
                event = "eapol"
            if event is not None:
                elapsed = timestamp - start_wall
                values[event] = elapsed if values[event] is None else min(values[event], elapsed)
    if available["dhcp"]:
        for line, receipt in zip(bundle.logs["dhcp_client"], receipts):
            if not DHCP_EVENT.search(line):
                continue
            elapsed = (receipt["monotonic_ns"] - start_mono) / 1_000_000_000
            if elapsed >= 0:
                values["dhcp"] = elapsed if values["dhcp"] is None else min(values["dhcp"], elapsed)
    return {"seconds": values, "available": available}


def event_summary(rows: list[dict]) -> dict:
    summary = {}
    for event in EVENTS:
        values = [row["first_events"]["seconds"][event] for row in rows
                  if row["first_events"]["seconds"][event] is not None]
        clock = "dhcp" if event == "dhcp" else "capture"
        available = sum(row["first_events"]["available"][clock] for row in rows)
        summary[event] = {"n": len(values), "timing_available": available,
                          "min": min(values) if values else None,
                          "median": median(values) if values else None,
                          "max": max(values) if values else None}
    return summary


def observations(dataset: Path, binary=None) -> list[dict]:
    manifest = verify_manifest(dataset)
    groups = defaultdict(list)
    for entry in manifest["bundles"]:
        if entry["split"] != "dev":
            continue
        path = Path(dataset) / entry["path"]
        meta = json.loads((path / "meta.json").read_text(encoding="utf-8"))
        row = {
            "id": entry["id"], "run_status": meta["status"], "quarantined": entry["quarantined"],
            "read_error": None, "observed": meta.get("observed"),
            "window_recorded": meta.get("observation_window") is not None,
            "status_codes": [], "reason_codes": [],
            "reason_codes_by_direction": {direction: [] for direction in DIRECTIONS},
            "four_messages_observed": False, "lease_logged": False,
            "parser_returncode": None, "log_status_reason_lines": [],
            "first_events": {"seconds": dict.fromkeys(EVENTS), "available": {"capture": False, "dhcp": False}},
        }
        groups[meta["label"]].append(row)
        try:
            # Owner inspection accepts legacy captures explicitly. Evaluation and
            # dataset validation still require the current observation boundary.
            bundle = load_bundle(path, binary=binary, require_window=False)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            row["read_error"] = str(error)
            continue
        frames = list(bundle.frames.values())
        row["status_codes"] = sorted({frame["status_code"] for frame in frames if frame.get("status_code") is not None})
        row["reason_codes"] = sorted({frame["reason_code"] for frame in frames if frame.get("reason_code") is not None})
        row["reason_codes_by_direction"] = {
            direction: sorted({frame["reason_code"] for frame in frames
                               if frame.get("reason_code") is not None
                               and reason_direction(frame, meta["parameters"]) == direction})
            for direction in DIRECTIONS
        }
        row["four_messages_observed"] = "complete=yes" in bundle.stats
        row["lease_logged"] = any(LEASE.search(line) for line in bundle.logs["dhcp_client"])
        row["parser_returncode"] = bundle.returncode
        row["first_events"] = first_events(bundle)
        row["log_status_reason_lines"] = [
            f"{source}:{number}: {line}"
            for source, lines in bundle.logs.items()
            for number, line in enumerate(lines, 1)
            if re.search(r"\b(?:status|reason)(?:_code)?[= :]+\d+", line, re.IGNORECASE)
        ]
    result = []
    for label, rows in sorted(groups.items()):
        outcomes = observed_summary([{"label": label, "observed": row["observed"]} for row in rows])
        result.append({"label": label, "runs": rows, "observed_summary": outcomes["by_class"][label],
                       "first_events": event_summary(rows)})
    return result


def render_observations(groups: list[dict]) -> str:
    output = ["Dev observations only. Four messages observed is not proof of one valid handshake."]
    missing = sum(not row["window_recorded"] for group in groups for row in group["runs"])
    if missing:
        output.append(f"WARNING: {missing} legacy bundles lack an observation boundary; their evidence can include teardown.")
    output.extend([
        "| Class | Bundles | Failed | Quarantined | Read errors | Status | AP->STA reasons | STA->AP reasons | AP->broadcast reasons | Other reasons | Four messages | Lease logged |",
        "| --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- | ---: | ---: |",
    ])
    for group in groups:
        rows = group["runs"]
        readable = sum(row["read_error"] is None for row in rows)
        reasons = [str(sorted({code for row in rows for code in row["reason_codes_by_direction"][direction]}))
                   for direction in DIRECTIONS]
        statuses = sorted({code for row in rows for code in row["status_codes"]})
        output.append(f"| {group['label']} | {len(rows)} | {sum(row['run_status'] == 'failed' for row in rows)} "
                      f"| {sum(row['quarantined'] for row in rows)} | {len(rows) - readable} | {statuses} | "
                      + " | ".join(reasons)
                      + f" | {sum(row['four_messages_observed'] for row in rows)}/{readable} "
                      f"| {sum(row['lease_logged'] for row in rows)}/{readable} |")
    output.extend([
        "", "First event seconds from tested-station scenario start: min / median / max; n events / available timings / bundles.",
        "Auth/assoc/EAPOL-Key use target AP-STA capture timestamps. EAPOL-Key means classified messages 1-4, not every EAPOL event. DHCP uses client protocol-line receipt time; buffering may delay it. Missing origins are unavailable, never inferred.",
        "| Class | Auth | Assoc | EAPOL-Key | DHCP |", "| --- | --- | --- | --- | --- |",
    ])
    for group in groups:
        cells = []
        for event in EVENTS:
            summary = group["first_events"][event]
            times = " / ".join(f"{summary[name]:.3f}" for name in ("min", "median", "max")) if summary["n"] else "unavailable/no event"
            cells.append(f"{times}; {summary['n']}/{summary['timing_available']}/{len(group['runs'])}")
        output.append(f"| {group['label']} | " + " | ".join(cells) + " |")
    output.extend([
        "", "Recorded final queries (after the evidence window): distributions only; mismatches do not exclude or relabel.",
        "IPv4 presence is an interface address observation, not independent proof of DHCP assignment.",
        "| Class | WPA state | IPv4 present | AP associated | AP authorized | Failure completed+IPv4 | Control missing completion/IPv4 | Unknown outcome |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: |",
    ])
    for group in groups:
        summary = group["observed_summary"]
        cells = [json.dumps(summary[name], sort_keys=True) for name in
                 ("wpa_state", "ipv4_lease_present", "ap_associated", "ap_authorized")]
        flags = summary["mismatch_counts"]
        output.append(f"| {group['label']} | " + " | ".join(cells)
                      + f" | {flags['failure_completed_with_lease']} | {flags['ok_missing_completed_or_lease']} | {flags['outcome_unknown']} |")
    for group in groups:
        for row in group["runs"]:
            if row["read_error"]:
                output.append(f"    {row['id']}: READ ERROR: {row['read_error']}")
            output.extend(f"    {row['id']}: {line}" for line in row["log_status_reason_lines"])
    return "\n".join(output) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--binary")
    args = parser.parse_args()
    print(render_observations(observations(args.dataset, args.binary)), end="")


if __name__ == "__main__":
    main()
