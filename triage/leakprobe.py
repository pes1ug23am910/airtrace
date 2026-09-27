"""Probe whether simple observation sizes predict labels across dataset splits."""

import argparse
from collections import Counter
from datetime import datetime
import json
import math
from pathlib import Path
import random
import subprocess
import sys

from lab.manifest import verify_manifest
from triage.data import VIEW_SOURCES, load_bundle


SHUFFLE_SEED = 9173


def metadata_features(bundle, view="client"):
    """Use sizes/counts only; never names, identifiers, config contents or labels."""
    if view not in VIEW_SOURCES:
        raise ValueError("view must be client or full")
    features = {}
    for source in VIEW_SOURCES[view]:
        features[source + "_bytes"] = (bundle.path / (source + ".log")).stat().st_size
        features[source + "_lines"] = len(bundle.logs[source])
    features["capture_bytes"] = (bundle.path / "capture.pcap").stat().st_size
    features["frame_count"] = len(bundle.frames)
    start = datetime.fromisoformat(bundle.meta["started_at"])
    end = datetime.fromisoformat(bundle.meta["ended_at"])
    features["duration_seconds"] = (end - start).total_seconds()
    return features


def fit_centroids(rows):
    """Fit feature scaling and centroids on dev rows only, with stable tie breaks."""
    if not rows:
        raise ValueError("the probe needs at least one usable dev bundle")
    names = sorted(rows[0]["features"])
    if any(sorted(row["features"]) != names for row in rows):
        raise ValueError("feature names differ between bundles")
    means = {}
    scales = {}
    for name in names:
        values = [row["features"][name] for row in rows]
        means[name] = sum(values) / len(values)
        variance = sum((value - means[name]) ** 2 for value in values) / len(values)
        scales[name] = math.sqrt(variance) or 1.0
    labels = sorted({row["label"] for row in rows})
    centroids = {}
    for label in labels:
        members = [row for row in rows if row["label"] == label]
        centroids[label] = [
            sum((row["features"][name] - means[name]) / scales[name] for row in members)
            / len(members) for name in names]
    counts = Counter(row["label"] for row in rows)
    majority = min(counts, key=lambda label: (-counts[label], label))
    return {"features": names, "means": means, "scales": scales,
            "centroids": centroids, "majority_label": majority}


def predict(classifier, features):
    vector = [(features[name] - classifier["means"][name]) / classifier["scales"][name]
              for name in classifier["features"]]
    distances = {}
    for label, centroid in classifier["centroids"].items():
        distances[label] = sum((left - right) ** 2 for left, right in zip(vector, centroid))
    return min(distances, key=lambda label: (distances[label], label))


def compare(dev, test):
    if not test:
        raise ValueError("the probe needs at least one usable test bundle")
    classifier = fit_centroids(dev)
    labels = [row["label"] for row in dev]
    random.Random(SHUFFLE_SEED).shuffle(labels)
    shuffled_dev = []
    for row, label in zip(dev, labels):
        shuffled_dev.append({"features": row["features"], "label": label})
    control = fit_centroids(shuffled_dev)
    predictions = []
    for row in test:
        predictions.append({"bundle_id": row["bundle_id"], "label": row["label"],
                            "prediction": predict(classifier, row["features"]),
                            "shuffled_prediction": predict(control, row["features"])})
    correct = sum(row["prediction"] == row["label"] for row in predictions)
    accuracy = correct / len(test)
    shuffled = sum(row["shuffled_prediction"] == row["label"] for row in predictions) / len(test)
    majority = classifier["majority_label"]
    baseline_correct = sum(row["label"] == majority for row in test)
    baseline = baseline_correct / len(test)
    return {"test_accuracy": accuracy, "majority_baseline_accuracy": baseline,
            "majority_label_from_dev": majority, "shuffled_label_accuracy": shuffled,
            "accuracy_above_baseline": accuracy - baseline,
            "flag": (correct - baseline_correct) * 5 > len(test),
            "classifier": classifier, "test_predictions": predictions}


def probe(dataset, *, binary=None, view="client"):
    if view not in VIEW_SOURCES:
        raise ValueError("view must be client or full")
    dataset = Path(dataset)
    manifest = verify_manifest(dataset)
    rows = {"dev": [], "test": []}
    excluded = []
    errors = []
    for entry in manifest["bundles"]:
        if entry["quarantined"]:
            excluded.append({"bundle_id": entry["id"], "split": entry["split"],
                             "reasons": entry["quarantine_reasons"]})
            continue
        try:
            bundle = load_bundle(dataset / entry["path"], binary=binary)
            features = metadata_features(bundle, view)
            rows[entry["split"]].append({"bundle_id": entry["id"],
                                          "label": bundle.meta["label"], "features": features})
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append({"bundle_id": entry["id"], "split": entry["split"],
                           "error": str(error)})
    result = {
        "view": view, "shuffle_seed": SHUFFLE_SEED,
        "generator_commit": manifest["generator_commit"],
        "counts": {"manifest_bundles": len(manifest["bundles"]),
                   "dev": len(rows["dev"]), "test": len(rows["test"]),
                   "quarantined": len(excluded), "read_errors": len(errors)},
        "excluded": excluded, "read_errors": errors,
        "limitations": (
            "This is a contamination diagnostic, not causal proof. Legitimate faults can change "
            "log volume, frame counts and duration. A single shuffled-label control is noisy; "
            "failure to beat the baseline does not establish absence of leakage. "
            "Scaling, centroids and the majority class use dev only; test labels only score predictions."),
    }
    if rows["dev"] and rows["test"]:
        result.update(compare(rows["dev"], rows["test"]))
        result["status"] = "ok"
        result["warning"] = (
            "POSSIBLE CONTAMINATION: metadata accuracy exceeds the majority baseline by more than 20 percentage points. Inspect the dataset."
            if result["flag"] else None)
    else:
        result.update({"status": "unavailable", "test_accuracy": None,
                       "majority_baseline_accuracy": None, "shuffled_label_accuracy": None,
                       "flag": False, "warning": "Usable dev and test bundles are both required."})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--airtrace", type=Path)
    parser.add_argument("--view", choices=tuple(VIEW_SOURCES), default="client")
    args = parser.parse_args(argv)
    try:
        result = probe(args.dataset, binary=args.airtrace, view=args.view)
    except (OSError, ValueError) as error:
        print("Leak probe refused: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["warning"]:
        print(result["warning"], file=sys.stderr)
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
