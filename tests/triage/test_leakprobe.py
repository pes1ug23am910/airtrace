"""Synthetic regression coverage for the metadata-only contamination check."""

import json
import os
from pathlib import Path
import shutil

import pytest

from lab.manifest import write_manifest
from lab.scenarios import bundle_id
from tests.triage.fixtures.build import build_bundle
from triage.data import load_bundle
from triage.leakprobe import compare, fit_centroids, main, metadata_features, predict, probe


@pytest.fixture
def dataset(tmp_path):
    directory = tmp_path / "dataset"
    for label, length in (("ok", 1), ("wrong_passphrase", 100)):
        for split, seeds in (("dev", (1000, 1001)), ("test", (1100, 1101))):
            for seed in seeds:
                path = build_bundle(directory / bundle_id(label, seed), label=label,
                                    seed=seed, split=split)
                # An intentionally contaminated client-visible volume signal.
                (path / "wpa_supplicant.log").write_text("observation line\n" * length,
                                                       encoding="utf-8")
    write_manifest(directory, 1000, "synthetic")
    return directory


@pytest.fixture
def binary():
    value = os.environ.get("AIRTRACE_BIN") or shutil.which("airtrace")
    if not value:
        local = Path(__file__).resolve().parents[2] / ".local" / "airtrace.exe"
        value = str(local) if local.is_file() else None
    if not value:
        pytest.skip("set AIRTRACE_BIN to the locally built parser")
    return value


def test_r12_synthetic_volume_leak_beats_baseline_and_flags(dataset, binary):
    result = probe(dataset, binary=binary)
    assert result == probe(dataset, binary=binary)
    assert result["view"] == "client"
    assert result["counts"] == {"manifest_bundles": 8, "dev": 4, "test": 4,
                                "quarantined": 0, "read_errors": 0}
    assert result["test_accuracy"] == 1
    assert result["majority_baseline_accuracy"] == 0.5
    assert result["flag"]
    assert "POSSIBLE CONTAMINATION" in result["warning"]
    assert 0 <= result["shuffled_label_accuracy"] <= 1
    assert "not causal proof" in result["limitations"]


def test_r12_feature_view_contains_only_sizes_counts_and_duration(dataset, binary):
    bundle = load_bundle(dataset / bundle_id("ok", 1000), binary=binary)
    features = metadata_features(bundle)
    assert set(features) == {"wpa_supplicant_bytes", "wpa_supplicant_lines",
                             "dhcp_client_bytes", "dhcp_client_lines", "capture_bytes",
                             "frame_count", "duration_seconds"}
    assert features["wpa_supplicant_lines"] == 1
    assert features["frame_count"] == 8
    assert features["duration_seconds"] == 1
    assert all(type(value) in (int, float) for value in features.values())
    bundle.meta["label"] = "ap_full"
    bundle.meta["parameters"] = {"ssid": "different"}
    assert metadata_features(bundle) == features
    full = metadata_features(bundle, "full")
    assert "hostapd_bytes" in full and "dhcp_server_lines" in full
    assert not any("hostapd" in key or "server" in key for key in features)


def test_r12_scaling_and_majority_fit_only_dev_with_deterministic_ties():
    dev = [{"bundle_id": "a", "label": "ok", "features": {"size": 0, "constant": 7}},
           {"bundle_id": "b", "label": "wrong_passphrase", "features": {"size": 10, "constant": 7}}]
    classifier = fit_centroids(dev)
    assert classifier["means"] == {"constant": 7, "size": 5}
    assert classifier["scales"] == {"constant": 1, "size": 5}
    assert classifier["majority_label"] == "ok"
    assert predict(classifier, {"size": 5, "constant": 7}) == "ok"
    test = [{"bundle_id": "c", "label": "wrong_passphrase",
             "features": {"size": 1000000, "constant": 7}}]
    comparison = compare(dev, test)
    assert comparison["classifier"] == classifier
    assert comparison["test_accuracy"] == 1
    assert comparison["majority_baseline_accuracy"] == 0
    test[0]["label"] = "ok"
    assert compare(dev, test)["test_predictions"][0]["prediction"] == "wrong_passphrase"


def test_r12_quarantine_and_read_errors_have_visible_denominators(dataset, binary):
    quarantine = dataset / bundle_id("ok", 1000)
    metadata = json.loads((quarantine / "meta.json").read_text())
    metadata["injection_verified"] = False
    (quarantine / "meta.json").write_text(json.dumps(metadata), encoding="utf-8")
    broken = dataset / bundle_id("wrong_passphrase", 1100)
    (broken / "capture.pcap").write_bytes(b"not a capture")
    write_manifest(dataset, 1000, "synthetic")
    result = probe(dataset, binary=binary)
    assert result["counts"]["quarantined"] == 1
    assert result["counts"]["read_errors"] == 1
    assert result["counts"]["dev"] == 3
    assert result["counts"]["test"] == 3
    assert result["excluded"][0]["bundle_id"] == quarantine.name
    assert result["read_errors"][0]["bundle_id"] == broken.name


def test_r12_manifest_tampering_refuses_probe(dataset, binary):
    (dataset / bundle_id("ok", 1000) / "dhcp_client.log").write_text("tampered")
    with pytest.raises(ValueError, match="manifest integrity"):
        probe(dataset, binary=binary)


def test_r12_twenty_point_threshold_is_strict_despite_float_rounding():
    dev = [{"bundle_id": "a", "label": "ok", "features": {"size": 0}},
           {"bundle_id": "b", "label": "wrong_passphrase", "features": {"size": 10}}]
    test = []
    for index in range(10):
        test.append({"bundle_id": str(index),
                     "label": "ok" if index < 6 else "wrong_passphrase",
                     "features": {"size": 10 if index in (6, 7) else 0}})
    result = compare(dev, test)
    assert result["test_accuracy"] == 0.8
    assert result["majority_baseline_accuracy"] == 0.6
    assert not result["flag"]
    test[-1]["features"]["size"] = 10
    assert compare(dev, test)["flag"]


def test_r12_cli_reports_loud_flag_and_requires_both_splits(dataset, binary, capsys):
    assert main([str(dataset), "--airtrace", str(binary)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["flag"]
    assert "POSSIBLE CONTAMINATION" in captured.err
    for path in dataset.glob("*/meta.json"):
        metadata = json.loads(path.read_text())
        if metadata["split"] == "test":
            metadata["injection_verified"] = False
            path.write_text(json.dumps(metadata), encoding="utf-8")
    write_manifest(dataset, 1000, "synthetic")
    assert main([str(dataset), "--airtrace", str(binary), "--view", "full"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "unavailable"
    assert result["view"] == "full"
    assert result["counts"]["test"] == 0
