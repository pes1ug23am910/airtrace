"""Named offline regressions for lab isolation and verification reviews."""

import json
from pathlib import Path
from dataclasses import replace
from types import SimpleNamespace
from io import BytesIO

import pytest

from lab.manifest import VERSION_TOOLS, validate_meta, verify_manifest, write_manifest
from lab.run_lab import Executor, command_plan, run_bundle, tool_versions
from lab.scenarios import CAUSAL_KEYS, CLASS_IDS, PARAMETER_RANGES, SCENARIOS, bundle_id, draw_parameters, render_configs
from lab.scrub import SCRUB_RULES, scrub_bundle_logs, scrub_control_lines
from lab.verify import check_capture_health, config_values, verification_commands, verify_injection
from lab.window import LogRecorder
from tests.triage.fixtures.build import capture_bytes


def fake_run(monkeypatch, directory, class_id="dhcp_no_server", injection=True, capture=True, observed_failure=False):
    """Fake daemons produce all visible text; the harness only retains/removes it."""
    produced = {}

    class FakeExecutor(Executor):
        def __init__(self, directory):
            super().__init__(directory)

        def execute(self, step):
            if step["kind"] == "start":
                text = "daemon started\ndaemon event retained\n"
                if step["log"] in ("hostapd.log", "wpa_supplicant.log"):
                    text += "RX ctrl_iface - hexdump_ascii(len=40):\n    DEAUTHENTICATE 02:11:22:33:44:55 reason=3\n"
                produced[step["log"]] = text
                recorder = LogRecorder(BytesIO(text.encode()), directory / "raw" / step["log"]).start()
                recorder.finish()
                self.recorders[step["log"]] = recorder
                self.processes.append((SimpleNamespace(poll=lambda: 0, returncode=0), recorder, step))
                if step["log"] == "tcpdump.log":
                    (directory / "raw" / "capture.pcap").write_bytes(capture_bytes())

        def healthy(self):
            pass

        def cleanup(self, commands):
            return []

    monkeypatch.setattr("lab.run_lab.Executor", FakeExecutor)
    monkeypatch.setattr("lab.run_lab.discover_phys", lambda: ["phy0", "phy1", "phy2"])
    monkeypatch.setattr("lab.run_lab.verify_injection", lambda *args: (injection, [{"check": "fake control", "passed": injection}]))
    def observed(*args):
        if observed_failure:
            raise TimeoutError("synthetic final status timeout")
        return {"wpa_state": "DISCONNECTED", "ipv4_lease_present": False,
                "ap_associated": False, "ap_authorized": False}
    monkeypatch.setattr("lab.run_lab.collect_observed", observed)
    monkeypatch.setattr("lab.run_lab.check_capture_health", lambda *args: {"healthy": capture, "ap_beacons": int(capture), "error": None})
    accepted = run_bundle(class_id, "dev", 1000, directory, "a" * 40, {"python": "fake"})
    return accepted, produced


@pytest.mark.parametrize("class_id", CLASS_IDS)
def test_r1_generated_visible_lines_are_only_daemon_output(tmp_path, monkeypatch, class_id):
    directory = tmp_path / bundle_id(class_id, 1000)
    accepted, produced = fake_run(monkeypatch, directory, class_id=class_id)
    assert accepted
    if class_id == "dhcp_no_server":
        assert (directory / "dhcp_server.log").read_text(encoding="utf-8") == ""
    meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    assert meta["dhcp_server_started"] == (class_id != "dhcp_no_server")
    for source in ("hostapd", "wpa_supplicant", "dhcp_client", "dhcp_server"):
        actual = (directory / (source + ".log")).read_text(encoding="utf-8").splitlines()
        original = produced.get(source + ".log", "").splitlines()
        assert all(line in original for line in actual)
        assert not any("DEAUTHENTICATE" in line or "RX ctrl_iface" in line for line in actual)


def test_r2_uniform_control_scrub_removes_commands_and_continuations_preserves_order(tmp_path):
    original = ("1.0: AP-ENABLED\n2.0: RX ctrl_iface - hexdump_ascii(len=42):\n"
                "    44 45 41 55 DEAUTHENTICATE address reason=3\n"
                "    continuation\n3.0: STA associated\n"
                "4.0: RX ctrl_iface: STA address\n5.0: CTRL_IFACE: STATUS\n6.0: event\n")
    for source in SCRUB_RULES["sources"]:
        (tmp_path / (source + ".log")).write_text(original, encoding="utf-8")
    record = scrub_bundle_logs(tmp_path)
    assert record["rules"] == SCRUB_RULES
    assert record["removed_lines"] == {"hostapd": 5, "wpa_supplicant": 5}
    for source in SCRUB_RULES["sources"]:
        result = (tmp_path / (source + ".log")).read_text(encoding="utf-8")
        assert result == "1.0: AP-ENABLED\n3.0: STA associated\n6.0: event\n"
        assert "DEAUTHENTICATE" not in result and "STA address" not in result and "STATUS" not in result


@pytest.mark.parametrize("class_id", CLASS_IDS)
def test_r3_configs_differ_from_control_only_in_declared_causal_keys(class_id):
    parameters = draw_parameters(1000)
    baseline = render_configs("ok", parameters, "/fixed/path")
    fault = render_configs(class_id, parameters, "/fixed/path")
    for scope, filename in (("ap", "hostapd.conf"), ("station", "station.conf")):
        before, after = config_values(baseline[filename]), config_values(fault[filename])
        differences = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
        assert differences == set(CAUSAL_KEYS[class_id][scope])
    actions = SCENARIOS[class_id].actions
    if not SCENARIOS[class_id].dhcp_server:
        actions += ("omit_dhcp_server",)
    assert set(actions) == set(CAUSAL_KEYS[class_id]["actions"])
    station = config_values(fault["station.conf"])
    assert station["ieee80211w"] == ("0" if class_id == "pmf_required_unsupported" else "1")


def test_r4_all_wireless_daemons_use_debug_not_message_dump(tmp_path):
    commands, _ = command_plan("ap_full", 1000, tmp_path)
    daemons = [step["argv"] for step in commands if step["kind"] == "start" and
               ("hostapd" in step["argv"] or "wpa_supplicant" in step["argv"])]
    assert len(daemons) == 3
    assert all("-d" in argv and "-t" in argv and "-dd" not in argv for argv in daemons)


@pytest.mark.parametrize("injection,capture,reason", [(False, True, "injection_unverified"), (True, False, "capture_unhealthy")])
def test_r9_failed_verification_quarantines_preserves_label_and_manifest(tmp_path, monkeypatch, injection, capture, reason):
    directory = tmp_path / bundle_id("dhcp_no_server", 1000)
    accepted, produced = fake_run(monkeypatch, directory, injection=injection, capture=capture)
    assert not accepted
    meta = validate_meta(json.loads((directory / "meta.json").read_text(encoding="utf-8")))
    assert meta.label == "dhcp_no_server" and meta.status == "ok"
    assert meta.quarantined and reason in meta.quarantine_reasons
    assert directory.exists() and (directory / "capture.pcap").exists()
    manifest = write_manifest(tmp_path, 1000, "a" * 40)
    assert manifest["quarantine"]["total"] == 1
    assert manifest["quarantine"]["by_reason"][reason] == 1
    assert verify_manifest(tmp_path) == manifest


@pytest.mark.parametrize("class_id", CLASS_IDS)
def test_r9_class_injection_checks_use_control_queries_and_process_state(tmp_path, class_id):
    # A generated token may contain FAIL without being a failed control reply.
    parameters = replace(draw_parameters(1000), ssid="airtrace-FAILabcd1234")
    for name, content in render_configs(class_id, parameters, str(tmp_path)).items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    # Contradictory text is irrelevant to injection verification.
    (tmp_path / "hostapd.log").write_text("misleading outcome\n", encoding="utf-8")
    commands = verification_commands(class_id, 1000, tmp_path, parameters)
    outputs = {
        "ap_status": "state=ENABLED", "ap_config": f"ssid={parameters.ssid}\nkey_mgmt={'SAE' if class_id == 'akm_mismatch' else 'WPA-PSK'}",
        "station_status": "wpa_state=DISCONNECTED" if class_id in ("ok", "dhcp_no_server") else "wpa_state=COMPLETED",
        "station_ssid": parameters.absent_ssid if class_id == "ssid_not_found" else parameters.ssid,
        "station_pmf": "0" if class_id == "pmf_required_unsupported" else "1",
        "deny_acl": parameters.station_mac, "occupant_authorized": "flags=[AUTHORIZED]",
    }
    class FakeExecutor:
        processes = [(SimpleNamespace(poll=lambda: None), None, {"log": log}) for log in
                     ("hostapd.log", "wpa_supplicant.log", "dhcp_server.log") if not (class_id == "dhcp_no_server" and log == "dhcp_server.log")]
        records = [{"argv": ["wpa_cli", "status"], "stdout": "wpa_state=COMPLETED", "returncode": 0},
                   {"argv": ["hostapd_cli", "deauthenticate"], "stdout": "OK", "returncode": 0}]
        def run(self, argv, timeout, check):
            key = next(name for name, command in commands.items() if command == argv)
            return SimpleNamespace(returncode=0, stdout=outputs[key], stderr="")
    verified, checks = verify_injection(FakeExecutor(), class_id, 1000, tmp_path, parameters)
    assert verified and all(check["passed"] for check in checks)
    assert not {"station_handshake_completed", "dhcp_address_assigned"}.intersection(check["check"] for check in checks)
    assert not any(".log" in json.dumps(check.get("detail", {})) for check in checks if check["check"].endswith("_query"))


def test_r9_capture_health_requires_beacon_from_configured_ap(tmp_path, monkeypatch):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic")
    def completed(ap):
        return SimpleNamespace(returncode=0, stdout=json.dumps({"type_id": 0, "subtype_id": 8, "bssid": ap}), stderr="Frames: 1")
    monkeypatch.setattr("lab.verify.subprocess.run", lambda *args, **kwargs: completed("02:11:22:33:44:55"))
    assert check_capture_health(capture, "02:11:22:33:44:55")["healthy"]
    assert not check_capture_health(capture, "02:11:22:33:44:66")["healthy"]


def test_r10_seed_and_parameter_ranges_are_disjoint_and_deterministic(tmp_path):
    for seed in range(50):
        dev, test = draw_parameters(seed, "dev"), draw_parameters(seed, "test")
        assert dev == draw_parameters(seed, "dev") and test == draw_parameters(seed, "test")
        assert 1 <= dev.channel <= 6 < test.channel <= 11
        assert 0.2 <= dev.ap_delay <= 1.2 < 1.5 <= test.ap_delay <= 3.0
        assert 0.2 <= dev.station_delay <= 1.2 < 1.5 <= test.station_delay <= 3.0
    manifest = write_manifest(tmp_path, 1000, "a" * 40)
    assert manifest["parameter_ranges"] == PARAMETER_RANGES


def test_r11_manifest_records_bundle_environment_and_scrub_rule(tmp_path, monkeypatch):
    directory = tmp_path / bundle_id("dhcp_no_server", 1000)
    fake_run(monkeypatch, directory)
    manifest = write_manifest(tmp_path, 1000, "a" * 40)
    entry = manifest["bundles"][0]
    assert entry["environment"]["kernel"]
    assert entry["environment"]["tool_versions"]["python"] == "fake"
    assert set(VERSION_TOOLS).issubset(entry["environment"]["tool_versions"])
    assert entry["environment"]["tool_versions"]["tshark"] == "unavailable: not recorded"
    assert entry["log_scrub"]["rules"] == SCRUB_RULES
    assert entry["log_scrub"]["removed_lines"] == {"hostapd": 2, "wpa_supplicant": 2}


def test_r11_tool_versions_include_every_relevant_binary_and_optional_tshark(monkeypatch):
    def probe(argv, **kwargs):
        assert kwargs["timeout"] == 10
        if argv[0] == "tshark":
            raise FileNotFoundError("not installed")
        return SimpleNamespace(stdout="version text", stderr="")
    monkeypatch.setattr("lab.run_lab.subprocess.run", probe)
    versions = tool_versions()
    assert {"hostapd", "wpa_supplicant", "dnsmasq", "udhcpc", "tcpdump", "tshark", "python"}.issubset(versions)
    assert versions["tshark"].startswith("unavailable:")


def test_r2_scrub_continuation_crosses_blank_lines_but_stops_at_new_event():
    text = "RX ctrl_iface: dump\n    44 45\n\n    DEAUTHENTICATE address\nnext daemon event\n    legitimate continuation\n"
    clean, count = scrub_control_lines(text)
    assert count == 4
    assert clean == "next daemon event\n    legitimate continuation\n"


def test_r2_scrub_removes_colonless_handled_command_lines_from_hostap():
    # Real hostap 2.11 debug strings: src/ap/ctrl_iface_ap.c logs "CTRL_IFACE DEAUTHENTICATE %s",
    # hostapd/ctrl_iface.c logs "CTRL_IFACE GET '%s'", wpa_supplicant logs "CTRL_IFACE: GET_NETWORK ...".
    text = ("1.0: wlan0: AP-STA-CONNECTED 02:11:22:33:44:55\n"
            "2.0: wlan0: CTRL_IFACE DEAUTHENTICATE 02:11:22:33:44:55\n"
            "3.0: CTRL_IFACE GET 'version'\n"
            "4.0: CTRL_IFACE: GET_NETWORK id=0 name='ieee80211w'\n"
            "5.0: wlan0: AP-STA-DISCONNECTED 02:11:22:33:44:55\n"
            "6.0: wlan1: CTRL-EVENT-DISCONNECTED bssid=02:11:22:33:44:55 reason=3\n")
    clean, count = scrub_control_lines(text)
    assert count == 3
    assert "CTRL_IFACE" not in clean and "DEAUTHENTICATE" not in clean
    assert "AP-STA-DISCONNECTED" in clean and "CTRL-EVENT-DISCONNECTED" in clean


def test_r9_manifest_rejects_tampered_quarantine_summary(tmp_path, monkeypatch):
    fake_run(monkeypatch, tmp_path / bundle_id("dhcp_no_server", 1000), injection=False)
    manifest = write_manifest(tmp_path, 1000, "a" * 40)
    manifest["quarantine"]["total"] = 0
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="quarantine summary"):
        verify_manifest(tmp_path)


@pytest.mark.parametrize("diagnostic", ["I/O failed\nFrames: 1", "Frames: 1\nERROR: statistics overflow", "Pcap record after frame 1\nFrames: 1"])
def test_r9_capture_health_rejects_parser_diagnostics_even_with_valid_beacon(tmp_path, monkeypatch, diagnostic):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic")
    frame = {"type_id": 0, "subtype_id": 8, "bssid": "02:11:22:33:44:55"}
    monkeypatch.setattr("lab.verify.subprocess.run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=1, stdout=json.dumps(frame), stderr=diagnostic))
    assert not check_capture_health(capture, frame["bssid"])["healthy"]


def test_r9_metadata_cannot_claim_verification_without_passing_checks(tmp_path, monkeypatch):
    directory = tmp_path / bundle_id("dhcp_no_server", 1000)
    fake_run(monkeypatch, directory)
    metadata = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    metadata["verification"][0]["passed"] = False
    with pytest.raises(ValueError, match="passing harness checks"):
        validate_meta(metadata)


def test_r9_metadata_cannot_claim_healthy_capture_without_beacons(tmp_path, monkeypatch):
    directory = tmp_path / bundle_id("dhcp_no_server", 1000)
    fake_run(monkeypatch, directory)
    metadata = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    metadata["capture_health"]["ap_beacons"] = 0
    with pytest.raises(ValueError, match="requires an AP beacon"):
        validate_meta(metadata)
