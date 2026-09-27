"""Record final control-query observations without changing labels or quarantine.

The IPv4 field records an address on wlan1, not an independent proof that DHCP
assigned it. These sequential queries describe post-observation state; a client
can reconnect between the capture cutoff and a query. Query failures stay unknown.
"""

from collections import Counter
import ipaddress
import json
import re
import subprocess

from lab.scenarios import bundle_id


OUTCOME_FIELDS = ("wpa_state", "ipv4_lease_present", "ap_associated", "ap_authorized")
MISMATCH_FIELDS = ("failure_completed_with_lease", "ok_missing_completed_or_lease", "outcome_unknown")
MAC_LINE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


def observation_commands(class_id, seed, directory):
    """Every class receives the same three state queries, after evidence closes."""
    token = bundle_id(class_id, seed)
    root = str(directory)
    ap = ["ip", "netns", "exec", f"at-{token}-ap", "hostapd_cli", "-p", f"{root}/ap-control", "-i", "wlan0"]
    station = ["ip", "netns", "exec", f"at-{token}-sta", "wpa_cli", "-p", f"{root}/sta-control", "-i", "wlan1"]
    return {
        "station_status": station + ["status"],
        "station_ipv4": ["ip", "-n", f"at-{token}-sta", "-j", "-4", "address", "show", "dev", "wlan1"],
        "ap_stations": ap + ["all_sta"],
    }


def _station_flags(text, station_mac):
    """Find the target's all_sta block; an empty successful listing means absent."""
    stations = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if MAC_LINE.fullmatch(line):
            current = line.lower()
            stations[current] = None
        elif line.startswith("flags=") and current is not None:
            stations[current] = set(re.findall(r"\[([^]]+)\]", line))
    if station_mac.lower() not in stations:
        if text.strip() and not stations:
            raise ValueError("AP listing contains no parseable station records")
        return False, False
    flags = stations[station_mac.lower()]
    if flags is None:
        raise ValueError("target station record is missing flags")
    return "ASSOC" in flags, "AUTHORIZED" in flags


def collect_observed(executor, class_id, seed, directory, parameters):
    """Return state and query provenance only; never determine run acceptance."""
    observed = dict.fromkeys(OUTCOME_FIELDS)
    observed["errors"] = []
    observed["queries"] = []
    responses = {}
    for name, argv in observation_commands(class_id, seed, directory).items():
        record = {"name": name, "argv": argv, "timeout_seconds": 10}
        try:
            result = executor.run(argv, timeout=10, check=False)
            record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            failed = any(line.strip() == "FAIL" or line.strip().startswith("FAIL-")
                         for line in result.stdout.splitlines())
            if result.returncode != 0 or failed:
                raise ValueError("query returned a failure")
            responses[name] = result.stdout
        except (OSError, RuntimeError, TimeoutError, ValueError, subprocess.SubprocessError) as error:
            record["error"] = f"{type(error).__name__}: {error}"
            observed["errors"].append({"query": name, "error": record["error"]})
        observed["queries"].append(record)

    def parse(name, operation):
        if name not in responses:
            return
        try:
            operation(responses[name])
        except (ValueError, TypeError, KeyError) as error:
            observed["errors"].append({"query": name, "error": f"{type(error).__name__}: {error}"})

    def station_state(text):
        values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        state = values.get("wpa_state", "").strip()
        if not state:
            raise ValueError("station status is missing wpa_state")
        observed["wpa_state"] = state

    def ipv4_state(text):
        interfaces = json.loads(text)
        if (not isinstance(interfaces, list) or len(interfaces) != 1
                or not isinstance(interfaces[0], dict) or interfaces[0].get("ifname") != "wlan1"):
            raise ValueError("IPv4 query did not return the station interface")
        addresses = interfaces[0].get("addr_info")
        if not isinstance(addresses, list):
            raise ValueError("IPv4 query is missing addr_info")
        assigned = False
        for address in addresses:
            if not isinstance(address, dict):
                raise ValueError("malformed station address record")
            if address.get("family") == "inet":
                ip = ipaddress.IPv4Address(address["local"])
                assigned = assigned or (not ip.is_loopback and not ip.is_unspecified)
        observed["ipv4_lease_present"] = assigned

    def ap_state(text):
        associated, authorized = _station_flags(text, parameters.station_mac)
        observed["ap_associated"] = associated
        observed["ap_authorized"] = authorized

    parse("station_status", station_state)
    parse("station_ipv4", ipv4_state)
    parse("ap_stations", ap_state)
    return observed


def observed_summary(records):
    """Count observed states and label/outcome discrepancies without exclusions."""
    by_class = {}
    total_flags = Counter(dict.fromkeys(MISMATCH_FIELDS, 0))
    grouped = {}
    for record in records:
        grouped.setdefault(record["label"], []).append(record.get("observed") or {})
    for label, observations in sorted(grouped.items()):
        fields = {name: Counter() for name in OUTCOME_FIELDS}
        joint = Counter()
        flags = Counter()
        for observed in observations:
            outcome = {name: observed.get(name) for name in OUTCOME_FIELDS}
            for name, value in outcome.items():
                key = "unknown" if value is None else str(value).lower() if isinstance(value, bool) else value
                fields[name][key] += 1
            joint[json.dumps(outcome, sort_keys=True)] += 1
            state, lease = outcome["wpa_state"], outcome["ipv4_lease_present"]
            if label != "ok" and state == "COMPLETED" and lease is True:
                flags["failure_completed_with_lease"] += 1
            if label == "ok" and ((state is not None and state != "COMPLETED") or lease is False):
                flags["ok_missing_completed_or_lease"] += 1
            if state is None or lease is None:
                flags["outcome_unknown"] += 1
        counts = {name: flags[name] for name in MISMATCH_FIELDS}
        total_flags.update(counts)
        by_class[label] = {
            "bundles": len(observations), "recorded": sum(bool(item) for item in observations),
            **{name: dict(sorted(counts.items())) for name, counts in fields.items()},
            "joint": [{**json.loads(value), "count": count} for value, count in sorted(joint.items())],
            "mismatch_counts": counts,
        }
    return {"by_class": by_class, "mismatch_counts": dict(total_flags)}
