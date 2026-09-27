import json
from pathlib import Path
import re
import string

import pytest

from lab.manifest import validate_meta, verify_manifest, write_manifest
from lab.run_lab import command_plan, main
from lab.scenarios import CLASS_IDS, bundle_id, draw_parameters, render_configs, seed_schedule


def metadata(seed=1000, split="dev", label="ok"):
    return {
        "label": label, "seed": seed, "split": split,
        "parameters": draw_parameters(seed, split).as_dict(), "kernel": "synthetic",
        "tool_versions": {"python": "synthetic"},
        "started_at": "2026-09-26T00:00:00+00:00", "ended_at": "2026-09-26T00:00:01+00:00",
        "status": "ok", "error": None, "generator_commit": "a" * 40,
        "injection_verified": True, "verification": [{"check": "synthetic", "passed": True}],
        "capture_health": {"healthy": True, "ap_beacons": 1},
        "quarantined": False, "quarantine_reasons": [],
    }


@pytest.mark.parametrize("seed", [0, 1, 1000, 2**40, -17])
def test_parameter_draws(seed):
    first = draw_parameters(seed)
    assert first == draw_parameters(seed)
    assert first != draw_parameters(seed + 1)
    assert 1 <= first.channel <= 11
    assert len(first.ssid) <= 32
    assert first.passphrase != first.wrong_passphrase
    addresses = [first.ap_mac, first.station_mac, first.occupant_mac]
    assert len(set(addresses)) == 3
    for address in addresses:
        assert int(address[:2], 16) & 3 == 2


@pytest.mark.parametrize("class_id", CLASS_IDS)
def test_configs_and_command_plan(class_id):
    p = draw_parameters(123)
    configs = render_configs(class_id, p, "/data/bundle")
    assert "hw_mode=g" in configs["hostapd.conf"]
    assert f"channel={p.channel}" in configs["hostapd.conf"]
    assert p.station_mac in configs["deny.txt"]
    steps, cleanup = command_plan(class_id, 123, Path("/data/bundle"))
    assert any(step.get("seconds", 0) >= 20 for step in steps)
    assert all(isinstance(step["argv"], list) and step["timeout"] > 0
               for step in steps if step["argv"] is not None)
    assert cleanup[-1] == ["modprobe", "-r", "mac80211_hwsim"]
    assert sum(step["argv"] and step["argv"][:3] == ["ip", "netns", "add"] for step in steps if step["argv"]) == 3
    server = any("dnsmasq" in step["argv"] for step in steps if step["argv"])
    assert server == (class_id != "dhcp_no_server")
    if class_id == "wrong_passphrase":
        assert p.wrong_passphrase in configs["station.conf"]
        assert p.passphrase not in configs["station.conf"]
    if class_id == "akm_mismatch":
        assert "wpa_key_mgmt=SAE\n" in configs["hostapd.conf"]
        assert "key_mgmt=WPA-PSK" in configs["station.conf"]
        assert "ieee80211w=1" in configs["station.conf"]
    if class_id == "pmf_required_unsupported":
        assert "ieee80211w=2" in configs["hostapd.conf"]
        assert "ieee80211w=0" in configs["station.conf"]
    if class_id == "ap_full":
        assert "max_num_sta=1" in configs["hostapd.conf"]
        occupied = next(i for i, step in enumerate(steps) if step.get("contains") == "[AUTHORIZED]")
        station = next(i for i, step in enumerate(steps) if step.get("log") == "wpa_supplicant.log")
        assert occupied < station
    if class_id == "ssid_not_found":
        assert p.absent_ssid in configs["station.conf"]
        assert p.absent_ssid not in configs["hostapd.conf"]


def test_seed_schedule():
    schedule = seed_schedule(500)
    assert schedule == [("dev", i) for i in range(500, 504)] + [("test", i) for i in range(600, 608)]
    assert len(schedule) * len(CLASS_IDS) == 108
    assert seed_schedule(500, 2) == schedule[:2]
    with pytest.raises(ValueError):
        seed_schedule(500, 13)


def test_dry_run_never_executes_or_writes(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("dry run attempted subprocess execution")
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    destination = tmp_path / "absent"
    assert main(["--classes", "ok", "ap_full", "--per-class", "1", "--out", str(destination), "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "tcpdump" in output and "radios=3" in output and "[AUTHORIZED]" in output
    assert not destination.exists()


def make_dataset(tmp_path, label="ok"):
    bundle = tmp_path / bundle_id(label, 1000)
    bundle.mkdir()
    (bundle / "meta.json").write_text(json.dumps(metadata(label=label)), encoding="utf-8")
    (bundle / "capture.pcap").write_bytes(b"fixture")
    for source in ("hostapd", "wpa_supplicant", "dhcp_server", "dhcp_client"):
        (bundle / f"{source}.log").write_text("fixture\n", encoding="utf-8")
    write_manifest(tmp_path, 1000, "a" * 40)
    return bundle


def test_manifest_integrity_and_tampering(tmp_path):
    bundle = make_dataset(tmp_path)
    manifest = verify_manifest(tmp_path)
    assert manifest["bundles"][0]["split"] == "dev"
    assert len(manifest["bundles"][0]["files"]["capture.pcap"]) == 64
    (bundle / "capture.pcap").write_bytes(b"changed")
    with pytest.raises(ValueError, match="integrity"):
        verify_manifest(tmp_path)


def test_manifest_rejects_untracked_files(tmp_path):
    bundle = make_dataset(tmp_path)
    (bundle / "extra.log").write_text("extra", encoding="utf-8")
    with pytest.raises(ValueError, match="missing from manifest"):
        verify_manifest(tmp_path)


@pytest.mark.parametrize("field,value", [("label", "invented"), ("split", "train"), ("ended_at", "2025-01-01T00:00:00Z"), ("status", "unknown")])
def test_invalid_metadata(field, value):
    data = metadata()
    data[field] = value
    with pytest.raises(ValueError):
        validate_meta(data)


def test_failed_metadata_requires_explanation():
    data = metadata()
    data["status"] = "failed"
    with pytest.raises(ValueError):
        validate_meta(data)


def test_manifest_rejects_wrong_split(tmp_path):
    bundle = tmp_path / bundle_id("ok", 1000)
    bundle.mkdir()
    (bundle / "meta.json").write_text(json.dumps(metadata(split="test")), encoding="utf-8")
    with pytest.raises(ValueError, match="split schedule"):
        write_manifest(tmp_path, 1000, "a" * 40)


def test_failed_run_is_recorded_and_cleanup_runs(tmp_path, monkeypatch):
    from lab.run_lab import run_bundle

    cleaned = []

    class FailingExecutor:
        def __init__(self, directory):
            self.records = [{"argv": ["modprobe", "mac80211_hwsim"], "error": "unavailable"}]
            self.observation_end = None

        def execute(self, step):
            raise RuntimeError("synthetic setup failure")

        def cleanup(self, commands):
            cleaned.extend(commands)
            return []

        def close_observation(self):
            raise ValueError("no capture from failed setup")

    monkeypatch.setattr("lab.run_lab.Executor", FailingExecutor)
    bundle = tmp_path / "failure"
    assert not run_bundle("wrong_passphrase", "dev", 1000, bundle, "a" * 40, {})
    meta = validate_meta(json.loads((bundle / "meta.json").read_text(encoding="utf-8")))
    assert meta.label == "wrong_passphrase"
    assert meta.status == "failed"
    assert "synthetic setup failure" in meta.error
    assert cleaned
    assert all((bundle / name).exists() for name in (
        "capture.pcap", "hostapd.log", "wpa_supplicant.log", "dhcp_server.log", "dhcp_client.log"))


def test_observe_retains_failed_dev_and_does_not_load_test(tmp_path, monkeypatch):
    from lab.observe import observations

    for seed, split in [(1000, "dev"), (1100, "test")]:
        bundle = tmp_path / bundle_id("ok", seed)
        bundle.mkdir()
        data = metadata(seed, split)
        data.update(status="failed", error="setup failed")
        (bundle / "meta.json").write_text(json.dumps(data), encoding="utf-8")
        (bundle / "capture.pcap").touch()
        for source in ("hostapd", "wpa_supplicant", "dhcp_server", "dhcp_client"):
            (bundle / f"{source}.log").touch()
    write_manifest(tmp_path, 1000, "a" * 40)
    loaded = []

    def failed_load(path, binary=None, **kwargs):
        loaded.append(path.name)
        raise ValueError("empty pcap")

    monkeypatch.setattr("lab.observe.load_bundle", failed_load)
    result = observations(tmp_path)
    assert loaded == [bundle_id("ok", 1000)]
    assert len(result[0]["runs"]) == 1
    assert result[0]["runs"][0]["read_error"] == "empty pcap"


def test_deadline_cannot_shorten_observation(tmp_path, monkeypatch):
    from lab.run_lab import Executor

    executor = Executor(tmp_path)
    monkeypatch.setattr("lab.run_lab.time.monotonic", lambda: 100.0)
    executor.deadline = 105.0
    slept = []
    monkeypatch.setattr("lab.run_lab.time.sleep", slept.append)
    with pytest.raises(TimeoutError, match="full observation"):
        executor.execute({"kind": "delay", "argv": None, "seconds": 30})
    assert not slept


def test_f1_opaque_bundle_names_and_manifest_do_not_reveal_class(tmp_path):
    for class_id in CLASS_IDS:
        bundle = make_dataset(tmp_path, class_id)
        assert re.fullmatch(r"[0-9a-f]{12}", bundle.name)
        assert bundle.name == bundle_id(class_id, 1000)
        assert all(name not in bundle.name for name in CLASS_IDS)
        assert json.loads((bundle / "meta.json").read_text(encoding="utf-8"))["label"] == class_id
    manifest = verify_manifest(tmp_path)
    assert len({entry["id"] for entry in manifest["bundles"]}) == len(CLASS_IDS)
    rendered_manifest = json.dumps(manifest["bundles"])
    for class_id in CLASS_IDS:
        assert class_id not in rendered_manifest
    for path in tmp_path.rglob("*"):
        assert all(class_id not in path.relative_to(tmp_path).as_posix() for class_id in CLASS_IDS)


def test_f1_manifest_rejects_label_bearing_directory(tmp_path):
    bundle = make_dataset(tmp_path)
    bundle.rename(tmp_path / "ok-1000")
    with pytest.raises(ValueError, match="opaque id"):
        write_manifest(tmp_path, 1000, "a" * 40)


def test_f2_ssids_share_distribution_and_rendered_names_do_not_encode_class():
    for seed in range(40):
        parameters = draw_parameters(seed)
        for ssid in (parameters.ssid, parameters.absent_ssid):
            assert ssid.startswith("airtrace-")
            assert len(ssid) == 21
            assert set(ssid[9:]) <= set(string.ascii_letters + string.digits)
        assert parameters.ssid != parameters.absent_ssid
        for class_id in CLASS_IDS:
            directory = Path("/dataset") / bundle_id(class_id, seed)
            configs = render_configs(class_id, parameters, directory.as_posix())
            station_ssid = re.search(r'    ssid="([^"]+)"', configs["station.conf"]).group(1)
            assert re.fullmatch(r"airtrace-[A-Za-z0-9]{12}", station_ssid)
            steps, cleanup = command_plan(class_id, seed, directory)
            rendered = json.dumps([configs, steps, cleanup])
            # Tokens can coincidentally contain a short class id, such as "ok".
            # Remove parameter values before inspecting static names and options.
            for value in parameters.as_dict().values():
                if isinstance(value, str):
                    rendered = rendered.replace(value, "VALUE")
            assert all(label not in rendered for label in CLASS_IDS)


def test_f6_dhcp_processes_have_separate_logs_and_manifest_requires_both(tmp_path):
    steps, _ = command_plan("ok", 1000, tmp_path)
    server = next(step for step in steps if step["argv"] and "dnsmasq" in step["argv"])
    client = next(step for step in steps if step["argv"] and "udhcpc" in step["argv"])
    assert server["log"] == "dhcp_server.log"
    assert client["log"] == "dhcp_client.log"
    bundle = make_dataset(tmp_path)
    for source in ("dhcp_server", "dhcp_client"):
        log = bundle / f"{source}.log"
        log.unlink()
        write_manifest(tmp_path, 1000, "a" * 40)
        with pytest.raises(ValueError, match="missing required files"):
            verify_manifest(tmp_path)
        log.write_text("fixture\n", encoding="utf-8")


def test_r1_f6_absent_server_log_is_empty_without_harness_text(tmp_path, monkeypatch):
    from lab.run_lab import run_bundle

    class FailingExecutor:
        def __init__(self, directory):
            self.records = []
            self.observation_end = None

        def execute(self, step):
            raise RuntimeError("synthetic setup failure")

        def cleanup(self, commands):
            return []

        def close_observation(self):
            raise ValueError("no capture from failed setup")

    monkeypatch.setattr("lab.run_lab.Executor", FailingExecutor)
    directory = tmp_path / bundle_id("dhcp_no_server", 1000)
    assert not run_bundle("dhcp_no_server", "dev", 1000, directory, "a" * 40, {})
    server = (directory / "dhcp_server.log").read_text(encoding="utf-8")
    assert server == ""
    assert all(label not in server for label in CLASS_IDS)
    assert (directory / "dhcp_client.log").read_text(encoding="utf-8") == ""


@pytest.mark.parametrize("split,count", [("dev", 4), ("test", 8), ("all", 12)])
def test_f7_split_selection_controls_opaque_dry_run_plans(tmp_path, monkeypatch, capsys, split, count):
    def forbidden(*args, **kwargs):
        raise AssertionError("dry run attempted subprocess execution")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    destination = tmp_path / "dataset"
    assert main(["--classes", "ok", "--split", split, "--out", str(destination), "--dry-run"]) == 0
    output = capsys.readouterr().out
    headers = [line for line in output.splitlines() if line.startswith("# bundle=")]
    assert len(headers) == count
    assert all("ok-" not in line for line in headers)
    for header, (part, seed) in zip(headers, seed_schedule(1000, split=split)):
        assert bundle_id("ok", seed) in header
        assert f"split={part}" in header
    assert not destination.exists()


def test_f7_workflow_timeout_and_optional_split_input():
    workflow = Path(".github/workflows/lab.yml").read_text(encoding="utf-8")
    assert "    timeout-minutes: 330\n" in workflow
    assert "  workflow_dispatch:\n    inputs:\n      split:" in workflow
    assert "        required: false\n        default: all\n" in workflow
    assert "          - dev\n          - test\n          - all\n" in workflow
    assert "LAB_SPLIT: ${{ inputs.split }}" in workflow
    assert '--split "$LAB_SPLIT"' in workflow
