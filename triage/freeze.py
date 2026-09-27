"""Freeze development choices before evaluating held-out bundles."""

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from pydantic import ValidationError

from lab.manifest import verify_manifest
from lab.scenarios import CAUSAL_KEYS
from lab.scrub import SCRUB_RULES
from triage.citations import CITATION_RULES_VERSION
from triage.llm import ModelConfig


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = {"capture.pcap", "hostapd.log", "wpa_supplicant.log",
                  "dhcp_server.log", "dhcp_client.log", "meta.json"}
DEFAULT_RAW_CHAR_BUDGET = 48000


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hash(value):
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def git_commit(root=ROOT):
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def verified_manifest(dataset):
    """Verify exact bundle contents, including failures, before trusting labels."""
    manifest = verify_manifest(Path(dataset))
    if not isinstance(manifest.get("bundles"), list) or not manifest["bundles"]:
        raise ValueError("Manifest needs a nonempty bundles list")
    identifiers = set()
    for bundle in manifest["bundles"]:
        identifier = bundle["id"]
        if identifier in identifiers:
            raise ValueError("Duplicate manifest bundle id")
        identifiers.add(identifier)
        if not REQUIRED_FILES.issubset(bundle["files"]):
            raise ValueError("Manifest bundle lacks required files")
    return manifest


def test_manifest_hash(manifest):
    test_bundles = sorted(
        [bundle for bundle in manifest["bundles"] if bundle["split"] == "test"],
        key=lambda bundle: bundle["id"],
    )
    if not test_bundles:
        raise ValueError("Cannot freeze a manifest without test bundles")
    return canonical_hash({
        "generator_commit": manifest.get("generator_commit"),
        "seed_base": manifest.get("seed_base"),
        "parameter_ranges": manifest.get("parameter_ranges"),
        "bundles": test_bundles,
    })


def source_hashes(root=ROOT):
    """Record working-tree source, since HEAD alone omits uncommitted edits."""
    root = Path(root)
    files = []
    for directory in ("triage", "lab", "src", "include"):
        files.extend((root / directory).rglob("*"))
    hashes = {}
    for path in sorted(files):
        if path.is_file() and path.suffix in {".py", ".txt", ".json", ".c", ".h"}:
            if path.name != "FROZEN.json":
                hashes[path.relative_to(root).as_posix()] = sha256(path)
    return hashes


def evaluation_settings(models, *, view="client", raw_char_budget=DEFAULT_RAW_CHAR_BUDGET):
    if view not in ("client", "full"):
        raise ValueError("view must be client or full")
    if type(raw_char_budget) is not int or raw_char_budget < 300:
        raise ValueError("raw character budget must be an integer of at least 300")
    data = json.loads(Path(models).read_text(encoding="utf-8"))
    entries = data.get("models", []) if isinstance(data, dict) else data
    limits = {}
    if not isinstance(entries, list):
        raise ValueError("models.json must contain a models list")
    for index, entry in enumerate(entries):
        try:
            model = ModelConfig.model_validate(entry)
        except ValidationError:
            raise ValueError(f"Invalid model configuration at index {index}") from None
        if model.name in limits:
            raise ValueError("Model names must be unique")
        limits[model.name] = {"model": model.model, "max_tokens": model.max_tokens,
                              "context_length": model.context_length}
    settings = {"view": view, "raw_char_budget": raw_char_budget, "model_limits": limits,
                "citation_rules_version": CITATION_RULES_VERSION,
                "scrub_rules": SCRUB_RULES, "label_map": CAUSAL_KEYS}
    return json.loads(json.dumps(settings))


def current_hashes(dataset, models, *, root=ROOT, raw_char_budget=DEFAULT_RAW_CHAR_BUDGET,
                   view="client"):
    settings = evaluation_settings(models, view=view, raw_char_budget=raw_char_budget)
    root = Path(root)
    manifest = verified_manifest(dataset)
    directory = root / "triage" / "prompts"
    prompts = sorted(path for path in directory.rglob("*") if path.is_file())
    if not prompts:
        raise ValueError("No prompt files to freeze")
    return {
        "test_manifest_sha256": test_manifest_hash(manifest),
        "rules_sha256": sha256(root / "triage" / "rules.py"),
        "prompt_sha256": {path.relative_to(directory).as_posix(): sha256(path) for path in prompts},
        "models_sha256": sha256(models),
        "source_tree_sha256": canonical_hash(source_hashes(root)),
        "evaluation_settings_sha256": canonical_hash(settings),
    }


def freeze(dataset, models, *, root=ROOT, destination=None,
           raw_char_budget=DEFAULT_RAW_CHAR_BUDGET, view="client"):
    root = Path(root)
    destination = Path(destination) if destination else root / "triage" / "FROZEN.json"
    record = {
        "format_version": 2,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_commit(root),
        "evaluation_settings": evaluation_settings(models, view=view, raw_char_budget=raw_char_budget),
        "hashes": current_hashes(dataset, models, root=root, raw_char_budget=raw_char_budget, view=view),
    }
    with destination.open("x", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return record


def verify_frozen(dataset, models, *, root=ROOT, frozen_path=None,
                  raw_char_budget=DEFAULT_RAW_CHAR_BUDGET, view="client"):
    root = Path(root)
    frozen_path = Path(frozen_path) if frozen_path else root / "triage" / "FROZEN.json"
    if not frozen_path.is_file():
        raise ValueError("Test evaluation requires triage/FROZEN.json; run python -m triage.freeze first")
    frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
    try:
        actual = current_hashes(dataset, models, root=root, raw_char_budget=raw_char_budget, view=view)
    except ValueError:
        raise ValueError("Frozen inputs changed; test evaluation refused") from None
    if (frozen.get("format_version") != 2 or frozen.get("hashes") != actual
            or canonical_hash(frozen.get("evaluation_settings")) != actual["evaluation_settings_sha256"]):
        raise ValueError("Frozen inputs changed; test evaluation refused")
    return frozen


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--models", type=Path, default=ROOT / "models.json")
    parser.add_argument("--raw-char-budget", type=int, default=DEFAULT_RAW_CHAR_BUDGET)
    parser.add_argument("--view", choices=("client", "full"), default="client")
    args = parser.parse_args(argv)
    try:
        record = freeze(args.dataset, args.models, raw_char_budget=args.raw_char_budget, view=args.view)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
