"""Bundle metadata and content-addressed dataset manifests."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lab.scenarios import CLASS_IDS, PARAMETER_RANGES, bundle_id, seed_schedule
from lab.outcomes import observed_summary


class BundleMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str
    seed: int
    split: Literal["dev", "test"]
    parameters: dict
    kernel: str
    tool_versions: dict[str, str]
    started_at: datetime
    ended_at: datetime
    status: Literal["ok", "failed"]
    error: str | None = None
    generator_commit: str
    commands: list[dict] = Field(default_factory=list)
    injection_verified: bool = False
    verification: list[dict] = Field(default_factory=list)
    capture_health: dict = Field(default_factory=lambda: {"healthy": False, "ap_beacons": 0, "error": "not checked"})
    quarantined: bool = True
    quarantine_reasons: list[str] = Field(default_factory=list)
    log_scrub: dict = Field(default_factory=dict)
    dhcp_server_started: bool | None = None
    scenario_started_at: datetime | None = None
    scenario_started_monotonic_ns: int | None = None
    observation_end: dict | None = None
    observation_window: dict | None = None
    observed: dict | None = None

    @field_validator("label")
    @classmethod
    def valid_label(cls, value):
        if value not in CLASS_IDS:
            raise ValueError("unknown injected class")
        return value

    @model_validator(mode="after")
    def valid_times_and_failure(self):
        if self.started_at.tzinfo is None or self.ended_at.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        if self.ended_at < self.started_at:
            raise ValueError("end timestamp precedes start")
        if self.scenario_started_at is not None and self.scenario_started_at.tzinfo is None:
            raise ValueError("scenario timestamp must include a timezone")
        if self.observed is not None:
            state = self.observed.get("wpa_state")
            if state is not None and not isinstance(state, str):
                raise ValueError("observed wpa_state must be a string or null")
            for name in ("ipv4_lease_present", "ap_associated", "ap_authorized"):
                if self.observed.get(name) is not None and type(self.observed[name]) is not bool:
                    raise ValueError(f"observed {name} must be boolean or null")
        if self.status == "failed" and not self.error:
            raise ValueError("failed bundles must record an error")
        if self.injection_verified and (not self.verification or any(check.get("passed") is not True for check in self.verification)):
            raise ValueError("verified injection must include passing harness checks")
        if type(self.capture_health.get("healthy")) is not bool:
            raise ValueError("capture health must contain a boolean healthy field")
        beacons = self.capture_health.get("ap_beacons", 0)
        if type(beacons) is not int or beacons < 0:
            raise ValueError("capture health must contain a nonnegative AP beacon count")
        if self.capture_health["healthy"] and beacons < 1:
            raise ValueError("healthy capture requires an AP beacon")
        reasons = []
        if self.status != "ok":
            reasons.append("run_failed")
        if not self.injection_verified:
            reasons.append("injection_unverified")
        if self.capture_health.get("healthy") is not True or self.capture_health.get("ap_beacons", 0) < 1:
            reasons.append("capture_unhealthy")
        self.quarantined = bool(reasons)
        self.quarantine_reasons = reasons
        return self


def validate_meta(data: dict) -> BundleMeta:
    return BundleMeta.model_validate(data)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=10, check=True,
    )
    return result.stdout.strip()


VERSION_TOOLS = ("hostapd", "wpa_supplicant", "dnsmasq", "udhcpc", "tcpdump", "tshark", "python")


def environment_record(meta: BundleMeta) -> dict:
    """Missing historical/synthetic version values are explicit, never invented."""
    versions = dict(meta.tool_versions)
    for name in VERSION_TOOLS:
        versions.setdefault(name, "unavailable: not recorded")
    return {"kernel": meta.kernel, "tool_versions": versions}


def quarantine_summary(entries: list[dict]) -> dict:
    return {
        "total": sum(entry["quarantined"] for entry in entries),
        "by_reason": {
            reason: sum(reason in entry["quarantine_reasons"] for entry in entries)
            for reason in ("run_failed", "injection_unverified", "capture_unhealthy")
        },
    }


def write_manifest(dataset: Path, seed_base: int, generator_commit: str | None = None) -> dict:
    dataset = Path(dataset)
    commit = generator_commit or git_commit()
    entries = []
    outcomes = []
    allowed = dict((seed, split) for split, seed in seed_schedule(seed_base))
    seen = set()
    for metadata in sorted(dataset.glob("*/meta.json")):
        bundle = metadata.parent
        meta = validate_meta(json.loads(metadata.read_text(encoding="utf-8")))
        outcomes.append({"label": meta.label, "observed": meta.observed})
        if allowed.get(meta.seed) != meta.split:
            raise ValueError(f"bundle violates seed split schedule: {bundle.name}")
        if bundle.name != bundle_id(meta.label, meta.seed):
            raise ValueError(f"bundle directory must use its opaque id: {bundle.name}")
        identity = (meta.label, meta.seed)
        if identity in seen:
            raise ValueError(f"duplicate class/seed: {identity}")
        seen.add(identity)
        files = {}
        for path in sorted(bundle.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"symlinks are not allowed: {path}")
            if path.is_file():
                files[path.relative_to(bundle).as_posix()] = sha256_file(path)
        entries.append({
            "id": bundle.name, "path": bundle.name, "split": meta.split,
            "seed": meta.seed, "files": files,
            "quarantined": meta.quarantined, "quarantine_reasons": meta.quarantine_reasons,
            "injection_verified": meta.injection_verified, "capture_health": meta.capture_health,
            "log_scrub": meta.log_scrub,
            "environment": environment_record(meta),
        })
    manifest = {"generator_commit": commit, "seed_base": seed_base, "bundles": entries,
                "parameter_ranges": PARAMETER_RANGES,
                "quarantine": quarantine_summary(entries), "observed_summary": observed_summary(outcomes)}
    (dataset / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def dataset_entries(dataset: Path, split: str | None = None) -> list[dict]:
    manifest = json.loads((Path(dataset) / "manifest.json").read_text(encoding="utf-8"))
    return [entry for entry in manifest["bundles"] if split is None or entry["split"] == split]


def verify_manifest(dataset: Path) -> dict:
    dataset = Path(dataset).resolve()
    if any(path.is_symlink() for path in dataset.rglob("*")):
        raise ValueError("symlinks are not allowed in a dataset")
    manifest = json.loads((dataset / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("parameter_ranges") != PARAMETER_RANGES:
        raise ValueError("manifest parameter ranges disagree with the generator")
    expected_files = set()
    seen = set()
    outcomes = []
    schedule = dict((seed, split) for split, seed in seed_schedule(manifest["seed_base"]))
    for entry in manifest["bundles"]:
        if set(entry) != {"id", "path", "split", "seed", "files", "quarantined", "quarantine_reasons",
                          "injection_verified", "capture_health", "log_scrub", "environment"}:
            raise ValueError("unexpected manifest bundle fields")
        if schedule.get(entry["seed"]) != entry["split"]:
            raise ValueError("manifest violates seed split schedule")
        bundle = (dataset / entry["path"]).resolve()
        if bundle.parent != dataset or bundle.name != entry["id"]:
            raise ValueError("unsafe bundle path in manifest")
        required = {"capture.pcap", "hostapd.log", "wpa_supplicant.log", "dhcp_server.log", "dhcp_client.log", "meta.json"}
        if not required.issubset(entry["files"]):
            raise ValueError(f"bundle is missing required files: {entry['id']}")
        for name, expected in entry["files"].items():
            path = (bundle / name).resolve()
            if bundle not in path.parents:
                raise ValueError("unsafe file path in manifest")
            if not path.is_file() or sha256_file(path) != expected:
                raise ValueError(f"manifest integrity mismatch: {entry['id']}/{name}")
            expected_files.add(path)
        meta = validate_meta(json.loads((bundle / "meta.json").read_text(encoding="utf-8")))
        outcomes.append({"label": meta.label, "observed": meta.observed})
        if bundle.name != bundle_id(meta.label, meta.seed):
            raise ValueError("bundle directory must use its opaque id")
        identity = (meta.label, meta.seed)
        if identity in seen:
            raise ValueError(f"duplicate class/seed in manifest: {identity}")
        seen.add(identity)
        if (meta.seed, meta.split) != (entry["seed"], entry["split"]):
            raise ValueError("manifest and bundle metadata disagree")
        expected_details = {
            "quarantined": meta.quarantined, "quarantine_reasons": meta.quarantine_reasons,
            "injection_verified": meta.injection_verified, "capture_health": meta.capture_health,
            "log_scrub": meta.log_scrub,
            "environment": environment_record(meta),
        }
        if any(entry[key] != value for key, value in expected_details.items()):
            raise ValueError("manifest and bundle verification/provenance disagree")
        if meta.generator_commit != manifest["generator_commit"]:
            raise ValueError("manifest and bundle generator commits disagree")
    if manifest.get("quarantine") != quarantine_summary(manifest["bundles"]):
        raise ValueError("manifest quarantine summary disagrees with bundle counts")
    if "observed_summary" in manifest or any(record["observed"] is not None for record in outcomes):
        if manifest.get("observed_summary") != observed_summary(outcomes):
            raise ValueError("manifest observed summary disagrees with bundle observations")
    actual_files = {path.resolve() for path in dataset.rglob("*") if path.is_file()}
    actual_files.discard(dataset / "manifest.json")
    if expected_files != actual_files:
        raise ValueError("dataset contains files missing from manifest")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--seed-base", type=int, required=True)
    args = parser.parse_args()
    write_manifest(args.dataset, args.seed_base)


if __name__ == "__main__":
    main()
