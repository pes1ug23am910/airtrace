"""Harness-side intervention checks, kept outside the observation logs."""

import json
import os
import re
from pathlib import Path
import subprocess

from lab.scenarios import bundle_id


def verification_commands(class_id, seed, directory, parameters):
    token = bundle_id(class_id, seed)
    root = str(directory)
    ap = ["ip", "netns", "exec", f"at-{token}-ap", "hostapd_cli", "-p", f"{root}/ap-control", "-i", "wlan0"]
    station = ["ip", "netns", "exec", f"at-{token}-sta", "wpa_cli", "-p", f"{root}/sta-control", "-i", "wlan1"]
    commands = {
        "ap_status": ap + ["status"],
        "ap_config": ap + ["get_config"],
        "station_status": station + ["status"],
        "station_ssid": station + ["get_network", "0", "ssid"],
        "station_pmf": station + ["get_network", "0", "ieee80211w"],
    }
    if class_id == "mac_denied":
        commands["deny_acl"] = ap + ["deny_acl", "SHOW"]
    if class_id == "ap_full":
        commands["occupant_authorized"] = ap + ["sta", parameters.occupant_mac]
    if class_id == "ok":
        commands["station_address"] = ["ip", "-n", f"at-{token}-sta", "-4", "address", "show", "dev", "wlan1"]
    return commands


def config_values(text):
    return dict(line.strip().split("=", 1) for line in text.splitlines() if "=" in line)


def verify_injection(executor, class_id, seed, directory, parameters):
    """Verify imposed settings and action acknowledgements, not diagnostic signatures.

    Some hostapd settings are absent from GET_CONFIG. For those, the proof is the
    exact file consumed by a live process plus a responsive, enabled AP. This does
    not prove an eventual client-visible failure, and is recorded as such.
    """
    checks = []

    def record(name, passed, detail):
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    responses = {}
    for name, argv in verification_commands(class_id, seed, directory, parameters).items():
        try:
            result = executor.run(argv, timeout=10, check=False)
            responses[name] = result.stdout.strip() if result.returncode == 0 else ""
            failed_reply = any(line.strip() == "FAIL" or line.strip().startswith("FAIL-")
                               for line in result.stdout.splitlines())
            record(name + "_query", result.returncode == 0 and not failed_reply,
                   {"argv": argv, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        except (OSError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
            responses[name] = ""
            record(name + "_query", False, str(error))

    ap = config_values((directory / "hostapd.conf").read_text(encoding="utf-8"))
    station = config_values((directory / "station.conf").read_text(encoding="utf-8"))
    active = {step["log"] for process, stream, step in executor.processes if process.poll() is None}
    record("daemon_processes_running", {"hostapd.log", "wpa_supplicant.log"}.issubset(active), sorted(active))
    record("ap_enabled", "state=ENABLED" in responses.get("ap_status", ""), responses.get("ap_status", ""))
    live_ap = config_values(responses.get("ap_config", ""))
    record("ap_ssid_loaded", live_ap.get("ssid") == parameters.ssid, live_ap.get("ssid"))
    expected_ssid = parameters.absent_ssid if class_id == "ssid_not_found" else parameters.ssid
    record("station_ssid_loaded", responses.get("station_ssid", "").strip('"') == expected_ssid,
           responses.get("station_ssid", ""))
    expected_pmf = "0" if class_id == "pmf_required_unsupported" else "1"
    record("station_pmf_loaded", responses.get("station_pmf") == expected_pmf, responses.get("station_pmf"))
    record("station_control_ready", "wpa_state=" in responses.get("station_status", ""), responses.get("station_status", ""))
    if class_id == "wrong_passphrase":
        record("different_passphrase_in_consumed_config", station.get("psk", "").strip('"') == parameters.wrong_passphrase
               and ap.get("wpa_passphrase") == parameters.passphrase and parameters.passphrase != parameters.wrong_passphrase,
               "live daemon configuration files contain the generated unequal credentials; outcome not inferred")
    elif class_id == "akm_mismatch":
        record("incompatible_akm_loaded", live_ap.get("key_mgmt", "").split() == ["SAE"]
               and station.get("key_mgmt") == "WPA-PSK", "AP GET_CONFIG SAE; live station configuration PSK")
    elif class_id == "pmf_required_unsupported":
        record("ap_pmf_required_in_consumed_config", ap.get("ieee80211w") == "2",
               "responsive AP process consumed ieee80211w=2; GET_CONFIG does not expose this setting")
    elif class_id == "mac_denied":
        record("station_in_live_deny_acl", parameters.station_mac.lower() in responses.get("deny_acl", "").lower(),
               responses.get("deny_acl", ""))
    elif class_id == "ap_full":
        record("occupied_single_station_limit", ap.get("max_num_sta") == "1"
               and "[AUTHORIZED]" in responses.get("occupant_authorized", ""),
               "responsive AP consumed max_num_sta=1; occupant STA query reports authorized")
    elif class_id == "dhcp_no_server":
        launched = [step for process, stream, step in executor.processes if step["log"] == "dhcp_server.log"]
        record("server_never_launched", not launched, "no server process launched in the newly created AP namespace")
        record("station_handshake_completed", "wpa_state=COMPLETED" in responses.get("station_status", ""), responses.get("station_status", ""))
    elif class_id == "ap_deauth":
        completed_before_action = False
        acknowledged = False
        for item in executor.records:
            argv = item.get("argv", [])
            if "status" in argv and "wpa_state=COMPLETED" in item.get("stdout", ""):
                completed_before_action = True
            if "deauthenticate" in argv and item.get("returncode") == 0 and "OK" in item.get("stdout", ""):
                acknowledged = completed_before_action
                break
        record("deauthentication_ack_after_completion", acknowledged,
               "successful station status query preceded the AP action acknowledgement")
    elif class_id == "ssid_not_found":
        record("distinct_networks_loaded", parameters.ssid != expected_ssid and live_ap.get("ssid") == parameters.ssid,
               "AP and station control queries report different SSIDs")
    elif class_id == "ok":
        record("station_handshake_completed", "wpa_state=COMPLETED" in responses.get("station_status", ""), responses.get("station_status", ""))
        record("dhcp_address_assigned", "inet 192.0.2." in responses.get("station_address", ""), responses.get("station_address", ""))
    if class_id != "dhcp_no_server":
        record("server_running", "dhcp_server.log" in active, "server process state in the AP namespace")
    return all(item["passed"] for item in checks), checks


def check_capture_health(capture: Path, ap_mac: str, binary=None) -> dict:
    result = {"healthy": False, "ap_beacons": 0, "exists": capture.is_file(), "error": None}
    if not result["exists"] or capture.stat().st_size == 0:
        result["error"] = "capture missing or empty"
        return result
    command = [str(binary or os.environ.get("AIRTRACE_BIN", "airtrace")), "parse", str(capture), "--jsonl", "--stats"]
    result["argv"] = command
    try:
        completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=30, check=False)
        result["returncode"] = completed.returncode
        before, separator, after = completed.stderr.partition("Frames: ")
        unexpected = [line for line in before.splitlines() if not re.fullmatch(r"Frame [0-9]+: .+", line)]
        if completed.returncode not in (0, 1) or not separator or unexpected or "ERROR:" in after:
            raise ValueError("capture parser error: " + completed.stderr[:1000])
        frames = [json.loads(line) for line in completed.stdout.splitlines()]
        if completed.returncode and not any("error" in frame for frame in frames):
            raise ValueError("unexplained capture parser failure")
        result["ap_beacons"] = sum(frame.get("type_id") == 0 and frame.get("subtype_id") == 8
                                   and (frame.get("bssid") or "").lower() == ap_mac.lower() for frame in frames)
        result["healthy"] = result["ap_beacons"] > 0
        if not result["healthy"]:
            result["error"] = "no beacon from the configured AP"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    return result
