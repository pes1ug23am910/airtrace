"""Owner observations use synthetic evidence, never a downloaded dataset."""

from copy import deepcopy
import json
from pathlib import Path

from lab.observe import (DIRECTIONS, event_summary, first_events, observations,
                         reason_direction, render_observations)
from lab.scenarios import bundle_id
from triage.data import Bundle


AP = "02:11:22:33:44:55"
STA = "02:66:77:88:99:aa"
OCCUPANT = "02:00:00:00:00:01"
PARAMETERS = {"ap_mac": AP, "station_mac": STA}
START = 1700000000


def frame(number, elapsed, *, receiver=STA, transmitter=AP, subtype=11, **values):
    return {"frame": number, "ts": START + elapsed, "type_id": 0,
            "subtype_id": subtype, "addrs": [receiver, transmitter, AP], **values}


def synthetic_bundle(label="ok", seed=1000, split="dev", observed=None):
    meta = {
        "label": label, "seed": seed, "split": split, "status": "ok",
        "parameters": PARAMETERS, "started_at": "2023-11-14T22:13:00+00:00",
        "scenario_started_at": "2023-11-14T22:13:20Z", "scenario_started_monotonic_ns": 10_000_000_000,
        "observation_window": {"logs": {"dhcp_client": {"lines": [
            {"monotonic_ns": 10_100_000_000}, {"monotonic_ns": 14_000_000_000},
            {"monotonic_ns": 15_000_000_000}]}}},
        "observed": observed,
    }
    frames = {
        1: frame(1, -1),
        2: frame(2, 0.1, receiver=OCCUPANT),
        3: frame(3, 0.2, receiver=OCCUPANT, subtype=1),
        4: frame(4, 0.3, receiver=OCCUPANT, type_id=2, eapol_msg=1),
        5: frame(5, 1, receiver=AP, transmitter=STA),
        6: frame(6, 2, subtype=0, receiver=AP, transmitter=STA),
        7: frame(7, 3, type_id=2, eapol_msg=1),
        8: frame(8, 4, receiver="ff:ff:ff:ff:ff:ff", subtype=12, reason_code=2),
        9: frame(9, 5, subtype=12, reason_code=3),
        10: frame(10, 6, receiver=AP, transmitter=STA, subtype=12, reason_code=4),
        11: frame(11, 7, receiver=OCCUPANT, subtype=12, reason_code=5),
    }
    logs = {"hostapd": [], "wpa_supplicant": [], "dhcp_server": [], "dhcp_client": [
        "udhcpc: started, v1.0", "udhcpc: broadcasting discover",
        "udhcpc: lease of 192.0.2.10 obtained, lease time 3600",
    ]}
    return Bundle(Path(bundle_id(label, seed)), meta, frames, logs, "complete=yes")


def fake_dataset(tmp_path, monkeypatch, bundles):
    entries = []
    by_name = {}
    loaded = []
    for bundle in bundles:
        path = tmp_path / bundle.path
        path.mkdir()
        (path / "meta.json").write_text(json.dumps(bundle.meta), encoding="utf-8")
        entries.append({"id": path.name, "path": path.name, "split": bundle.meta["split"], "quarantined": False})
        by_name[path.name] = bundle

    def load(path, binary=None, *, require_window=True):
        assert require_window is False
        loaded.append(path.name)
        return by_name[path.name]

    monkeypatch.setattr("lab.observe.verify_manifest", lambda path: {"bundles": entries})
    monkeypatch.setattr("lab.observe.load_bundle", load)
    return loaded


def test_r15_direction_separates_target_broadcast_and_occupant():
    bundle = synthetic_bundle()
    assert reason_direction(bundle.frames[9], PARAMETERS) == "ap_to_station"
    assert reason_direction(bundle.frames[10], PARAMETERS) == "station_to_ap"
    assert reason_direction(bundle.frames[8], PARAMETERS) == "ap_to_broadcast"
    assert reason_direction(bundle.frames[11], PARAMETERS) == "other"
    assert reason_direction({"addrs": [AP]}, PARAMETERS) == "other"
    assert reason_direction(frame(1, 0, transmitter=AP.upper(), receiver=STA.upper()), PARAMETERS) == "ap_to_station"


def test_r15_first_event_times_ignore_occupant_startup_and_pre_scenario_frames():
    result = first_events(synthetic_bundle())
    assert result["seconds"] == {"auth": 1, "assoc": 2, "eapol": 3, "dhcp": 4}
    assert result["available"] == {"capture": True, "dhcp": True}
    # Insertion order does not choose the first event when capture times differ.
    bundle = synthetic_bundle()
    bundle.frames[12] = frame(12, 0.5)
    assert first_events(bundle)["seconds"]["auth"] == 0.5


def test_r15_legacy_timing_is_unavailable_not_inferred_from_setup_or_log_text():
    bundle = synthetic_bundle()
    for key in ("scenario_started_at", "scenario_started_monotonic_ns", "observation_window"):
        bundle.meta.pop(key)
    bundle.logs["dhcp_client"][1] = "1700000004.0 udhcpc: broadcasting discover"
    result = first_events(bundle)
    assert result["seconds"] == dict.fromkeys(("auth", "assoc", "eapol", "dhcp"))
    assert result["available"] == {"capture": False, "dhcp": False}


def test_r15_eapol_timing_is_only_for_classified_key_messages():
    bundle = synthetic_bundle()
    bundle.frames[7]["eapol_msg"] = None
    assert first_events(bundle)["seconds"]["eapol"] is None
    bundle.frames[12] = frame(12, 6, type_id=2, eapol_msg=2)
    assert first_events(bundle)["seconds"]["eapol"] == 6


def test_r15_observe_is_dev_only_and_reports_direction_and_timing_denominators(tmp_path, monkeypatch):
    first = synthetic_bundle()
    second = synthetic_bundle(seed=1001)
    second.frames = {}
    second.logs["dhcp_client"] = []
    second.meta["observation_window"]["logs"]["dhcp_client"]["lines"] = []
    hidden = synthetic_bundle(seed=1100, split="test")
    loaded = fake_dataset(tmp_path, monkeypatch, [first, second, hidden])
    groups = observations(tmp_path)
    assert loaded == [first.path.name, second.path.name]
    group = groups[0]
    assert group["first_events"]["auth"] == {"n": 1, "timing_available": 2, "min": 1, "median": 1, "max": 1}
    assert group["runs"][0]["reason_codes_by_direction"] == dict(zip(DIRECTIONS, [[3], [4], [2], [5]]))
    rendered = render_observations(groups)
    assert "AP->STA reasons | STA->AP reasons | AP->broadcast reasons | Other reasons" in rendered
    assert "1.000 / 1.000 / 1.000; 1/2/2" in rendered
    assert "DHCP uses client protocol-line receipt time" in rendered
    assert hidden.path.name not in rendered


def test_r15_summary_reports_actual_min_median_max_not_missing_as_zero():
    rows = []
    for delay in (None, 1, 3, 9):
        result = first_events(synthetic_bundle())
        result["seconds"]["auth"] = delay
        rows.append({"first_events": result})
    assert event_summary(rows)["auth"] == {"n": 3, "timing_available": 4, "min": 1, "median": 3, "max": 9}


def test_r14_observe_distributions_flag_mismatches_without_exclusion_or_relabelling(tmp_path, monkeypatch):
    succeeded = {"wpa_state": "COMPLETED", "ipv4_lease_present": True,
                 "ap_associated": True, "ap_authorized": True}
    failed = {"wpa_state": "DISCONNECTED", "ipv4_lease_present": False,
              "ap_associated": False, "ap_authorized": False}
    bundles = [synthetic_bundle("wrong_passphrase", observed=succeeded),
               synthetic_bundle("ok", observed=failed), synthetic_bundle("ok", seed=1001)]
    fake_dataset(tmp_path, monkeypatch, bundles)
    before = deepcopy([bundle.meta for bundle in bundles])
    groups = observations(tmp_path)
    indexed = {group["label"]: group for group in groups}
    assert indexed["wrong_passphrase"]["observed_summary"]["mismatch_counts"]["failure_completed_with_lease"] == 1
    assert indexed["ok"]["observed_summary"]["mismatch_counts"] == {
        "failure_completed_with_lease": 0, "ok_missing_completed_or_lease": 1, "outcome_unknown": 1}
    assert indexed["ok"]["observed_summary"]["wpa_state"] == {"DISCONNECTED": 1, "unknown": 1}
    assert sum(len(group["runs"]) for group in groups) == 3
    assert all(not row["quarantined"] for group in groups for row in group["runs"])
    assert before == [bundle.meta for bundle in bundles]
    rendered = render_observations(groups)
    assert "mismatches do not exclude or relabel" in rendered
    assert "Failure completed+IPv4" in rendered


def test_r15_legacy_boundary_warning_is_explicit(tmp_path, monkeypatch):
    bundle = synthetic_bundle()
    bundle.meta.pop("observation_window")
    fake_dataset(tmp_path, monkeypatch, [bundle])
    rendered = render_observations(observations(tmp_path))
    assert "WARNING: 1 legacy bundles lack an observation boundary" in rendered
    assert "their evidence can include teardown" in rendered
