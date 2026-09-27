import json

import pytest

from lab.manifest import write_manifest
from lab.scenarios import bundle_id
from tests.triage.fixtures.build import build_bundle
from triage.freeze import current_hashes, freeze, verify_frozen


@pytest.fixture
def frozen_inputs(tmp_path):
    root = tmp_path / "source"
    prompts = root / "triage" / "prompts"
    prompts.mkdir(parents=True)
    (root / "triage" / "rules.py").write_text("RULES = ()\n", encoding="utf-8")
    (prompts / "common.txt").write_text("Use cited observations.\n", encoding="utf-8")
    models = root / "models.json"
    models.write_text("[]\n", encoding="utf-8")
    dataset = tmp_path / "dataset"
    build_bundle(dataset / bundle_id("ok", 1000), seed=1000)
    build_bundle(dataset / bundle_id("ok", 1100), seed=1100, split="test")
    write_manifest(dataset, 1000, "synthetic")
    return root, dataset, models


def test_freeze_roundtrip_and_no_overwrite(frozen_inputs):
    root, dataset, models = frozen_inputs
    frozen = freeze(dataset, models, root=root)
    assert verify_frozen(dataset, models, root=root) == frozen
    assert frozen["hashes"] == current_hashes(dataset, models, root=root)
    with pytest.raises(FileExistsError):
        freeze(dataset, models, root=root)
    assert verify_frozen(dataset, models, root=root) == frozen


@pytest.mark.parametrize("target", ["rules", "prompt", "added_prompt", "models", "source"])
def test_changes_refuse_held_out_evaluation(frozen_inputs, target):
    root, dataset, models = frozen_inputs
    freeze(dataset, models, root=root)
    files = {
        "rules": root / "triage" / "rules.py",
        "prompt": root / "triage" / "prompts" / "common.txt",
        "added_prompt": root / "triage" / "prompts" / "extra.txt",
        "models": models,
        "source": root / "triage" / "tools.py",
    }
    files[target].write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Frozen inputs changed"):
        verify_frozen(dataset, models, root=root)


@pytest.mark.parametrize("rewrite_manifest", [False, True])
def test_test_bundle_tampering_detected(frozen_inputs, rewrite_manifest):
    root, dataset, models = frozen_inputs
    freeze(dataset, models, root=root)
    (dataset / bundle_id("ok", 1100) / "capture.pcap").write_bytes(b"changed")
    if rewrite_manifest:
        write_manifest(dataset, 1000, "synthetic")
    with pytest.raises(ValueError):
        verify_frozen(dataset, models, root=root)


def test_test_manifest_label_cannot_be_changed(frozen_inputs):
    root, dataset, models = frozen_inputs
    freeze(dataset, models, root=root)
    metadata = dataset / bundle_id("ok", 1100) / "meta.json"
    value = json.loads(metadata.read_text(encoding="utf-8"))
    value["label"] = "wrong_passphrase"
    metadata.write_text(json.dumps(value), encoding="utf-8")
    metadata.parent.rename(dataset / bundle_id("wrong_passphrase", 1100))
    write_manifest(dataset, 1000, "synthetic")
    with pytest.raises(ValueError, match="Frozen inputs changed"):
        verify_frozen(dataset, models, root=root)


def test_dev_contents_are_not_part_of_test_manifest_hash(frozen_inputs):
    root, dataset, models = frozen_inputs
    frozen = freeze(dataset, models, root=root)
    (dataset / bundle_id("ok", 1000) / "dhcp_client.log").write_text("development-only change\n", encoding="utf-8")
    write_manifest(dataset, 1000, "synthetic")
    assert verify_frozen(dataset, models, root=root) == frozen


def test_no_test_split_cannot_be_frozen(frozen_inputs):
    root, dataset, models = frozen_inputs
    manifest = json.loads((dataset / "manifest.json").read_text(encoding="utf-8"))
    # Use a separate development-only dataset, leaving the original untouched.
    dev = dataset.parent / "development"
    build_bundle(dev / bundle_id("ok", 1000), seed=1000)
    write_manifest(dev, manifest["seed_base"], "synthetic")
    with pytest.raises(ValueError, match="without test bundles"):
        freeze(dev, models, root=root)


def test_missing_frozen_file_refuses(frozen_inputs):
    root, dataset, models = frozen_inputs
    with pytest.raises(ValueError, match="requires triage/FROZEN.json"):
        verify_frozen(dataset, models, root=root)


def test_f3_raw_budget_changes_refuse_held_out_evaluation(frozen_inputs):
    root, dataset, models = frozen_inputs
    record = freeze(dataset, models, root=root, raw_char_budget=48000)
    assert record["evaluation_settings"]["raw_char_budget"] == 48000
    with pytest.raises(ValueError, match="Frozen inputs changed"):
        verify_frozen(dataset, models, root=root, raw_char_budget=12000)


def test_r5_frozen_view_mismatch_is_refused(frozen_inputs):
    root, dataset, models = frozen_inputs
    frozen = freeze(dataset, models, root=root, view="client")
    assert frozen["evaluation_settings"]["view"] == "client"
    with pytest.raises(ValueError, match="Frozen inputs changed"):
        verify_frozen(dataset, models, root=root, view="full")


def test_r11_freeze_records_all_evaluation_choices(frozen_inputs):
    from triage.citations import CITATION_RULES_VERSION
    from lab.scrub import SCRUB_RULES
    from lab.scenarios import CAUSAL_KEYS
    root, dataset, models = frozen_inputs
    models.write_text(json.dumps([{"name": "local", "base_url": "http://localhost:11434/v1",
                                  "model": "explicit", "api_key_env": "", "supports_tools": True,
                                  "rpm": 8, "max_tokens": 8192, "context_length": 32768}]))
    frozen = freeze(dataset, models, root=root)
    settings = frozen["evaluation_settings"]
    assert settings["model_limits"]["local"] == {"model": "explicit", "max_tokens": 8192, "context_length": 32768}
    assert settings["citation_rules_version"] == CITATION_RULES_VERSION
    assert settings["scrub_rules"] == SCRUB_RULES
    assert settings["label_map"] == json.loads(json.dumps(CAUSAL_KEYS))
    path = root / "triage" / "FROZEN.json"
    frozen["evaluation_settings"]["view"] = "full"
    path.write_text(json.dumps(frozen))
    with pytest.raises(ValueError, match="Frozen inputs changed"):
        verify_frozen(dataset, models, root=root)
