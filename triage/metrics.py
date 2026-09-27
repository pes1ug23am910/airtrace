"""Bundle-level metrics with fixed-seed percentile bootstrap intervals."""

import itertools
import random
from collections import Counter, defaultdict

from triage.statistics import clopper_pearson, exact_mcnemar


CLASS_IDS = (
    "ok", "wrong_passphrase", "akm_mismatch", "pmf_required_unsupported",
    "mac_denied", "ap_full", "dhcp_no_server", "ap_deauth", "ssid_not_found",
)
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20260926


def percentile(values, fraction):
    """Linear interpolation between adjacent sorted observations."""
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def bootstrap_mean(values, *, seed=BOOTSTRAP_SEED, resamples=BOOTSTRAP_RESAMPLES):
    if not values:
        raise ValueError("Cannot bootstrap an empty set of bundles")
    if resamples < 1:
        raise ValueError("resamples must be positive")
    rng = random.Random(seed)
    means = []
    for _ in range(resamples):
        total = 0
        for _ in values:
            total += values[rng.randrange(len(values))]
        means.append(total / len(values))
    return [percentile(means, 0.025), percentile(means, 0.975)]


def exclusion_reason(row):
    if row.get("excluded"):
        return row.get("exclusion_reason") or "excluded"
    if row.get("outcome") in ("TRUNCATED", "CONTEXT_REJECTED"):
        return row["outcome"]
    return None


def group_metrics(rows):
    """Quarantine/truncation are excluded visibly; schema failures remain unknown."""
    if not rows:
        raise ValueError("No evaluation rows")
    exclusions = Counter(exclusion_reason(row) for row in rows if exclusion_reason(row))
    evaluated = [row for row in rows if exclusion_reason(row) is None]
    denominator = len(evaluated)
    columns = CLASS_IDS + ("unknown",)
    confusion = {label: {prediction: 0 for prediction in columns} for label in CLASS_IDS}
    correct = []
    for row in evaluated:
        confusion[row["label"]][row["prediction"]] += 1
        correct.append(int(row["label"] == row["prediction"]))
    recall = {}
    recall_intervals = {}
    recall_bootstrap = {}
    f1_scores = []
    for label in CLASS_IDS:
        true_positive = confusion[label][label]
        support = sum(confusion[label].values())
        predicted = sum(confusion[truth][label] for truth in CLASS_IDS)
        recall[label] = true_positive / support if support else None
        recall_intervals[label] = clopper_pearson(true_positive, support)
        class_correct = [int(row["prediction"] == label) for row in evaluated if row["label"] == label]
        recall_bootstrap[label] = bootstrap_mean(class_correct) if class_correct else [None, None]
        f1_denominator = support + predicted
        f1_scores.append(2 * true_positive / f1_denominator if f1_denominator else 0.0)
    cited_rows = [row for row in evaluated
                  if row["citations"]["valid"] + row["citations"]["invalid"] > 0]
    valid = sum(row["citations"]["valid"] for row in cited_rows)
    invalid = sum(row["citations"]["invalid"] for row in cited_rows)
    ambiguous = sum(row["citations"].get("ambiguous", 0) for row in cited_rows)
    automatic = sum(row["citations"].get("auto", 0) for row in rows)
    known_costs = [row["cost_inr"] for row in rows if row.get("cost_inr") is not None]
    latencies = [row["latency_ms"] for row in rows if row["latency_ms"] is not None]
    tokens = {}
    for kind in ("prompt", "completion", "total"):
        known = [row["tokens"].get(kind) for row in rows if row["tokens"].get(kind) is not None]
        tokens[kind] = {
            "mean_per_bundle": sum(known) / len(known) if known else None,
            "total": sum(known) if known else None,
            "bundles_with_usage": len(known),
        }
    count = len(rows)
    return {
        "bundles": count,
        "bundles_evaluated": denominator,
        "bundles_excluded": count - denominator,
        "excluded_reasons": dict(sorted(exclusions.items())),
        "truncated": sum(row.get("outcome") == "TRUNCATED" for row in rows),
        "truncation_suspected": sum(bool(row.get("truncation_suspected")) for row in rows),
        "schema_failures": sum(bool(row["schema_failure"]) for row in evaluated),
        "correct": sum(correct),
        "accuracy": sum(correct) / denominator if denominator else None,
        "accuracy_ci95": bootstrap_mean(correct) if correct else [None, None],
        "accuracy_clopper_pearson_ci95": clopper_pearson(sum(correct), denominator),
        "macro_f1": sum(f1_scores) / len(CLASS_IDS) if denominator else None,
        "per_class_recall": recall,
        "per_class_recall_clopper_pearson_ci95": recall_intervals,
        "per_class_recall_bootstrap_ci95": recall_bootstrap,
        "per_class_support": {label: sum(confusion[label].values()) for label in CLASS_IDS},
        "confusion_matrix": confusion,
        "unknown_rate": sum(row["prediction"] == "unknown" for row in evaluated) / denominator if denominator else None,
        "schema_failure_rate": sum(row["schema_failure"] for row in evaluated) / denominator if denominator else None,
        "execution_error_rate": sum(row["error"] is not None for row in rows) / count,
        "citation_all_valid_rate": sum(row["citations"]["all_valid"] for row in cited_rows) / len(cited_rows) if cited_rows else None,
        "citation_resolves_rate": valid / (valid + invalid) if valid + invalid else None,
        "citation_ambiguous_rate": ambiguous / (valid + invalid) if valid + invalid else None,
        "invalid_citation_rate": invalid / (valid + invalid) if valid + invalid else None,
        "ambiguous_citation_rate": ambiguous / (valid + invalid) if valid + invalid else None,
        "citation_counts": {"valid": valid, "invalid": invalid, "ambiguous": ambiguous,
                            "auto_excluded": automatic, "bundles_with_model_citations": len(cited_rows)},
        "cost_inr": {
            "total": sum(known_costs) if len(known_costs) == count else None,
            "known_subtotal": sum(known_costs) if known_costs else None,
            "mean_per_known_bundle": sum(known_costs) / len(known_costs) if known_costs else None,
            "bundles_with_cost": len(known_costs),
        },
        "latency_ms": {
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "bundles_measured": len(latencies),
        },
        "tokens_per_bundle": tokens,
    }


def compute_metrics(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["group"]].append(row)
    if not grouped:
        raise ValueError("No evaluation rows")
    groups = {}
    indexed = {}
    for name in sorted(grouped):
        group = grouped[name]
        indexed[name] = {row["bundle_id"]: row for row in group}
        if len(indexed[name]) != len(group):
            raise ValueError("Duplicate bundle in evaluation group: " + name)
        groups[name] = group_metrics(group)
    paired = []
    for left, right in itertools.combinations(sorted(groups), 2):
        if set(indexed[left]) != set(indexed[right]):
            raise ValueError("Paired comparison requires identical bundle sets")
        differences = []
        for bundle_id in sorted(indexed[left]):
            a = indexed[left][bundle_id]
            b = indexed[right][bundle_id]
            if a["label"] != b["label"]:
                raise ValueError("Paired bundle has inconsistent labels")
            if exclusion_reason(a) or exclusion_reason(b):
                continue
            differences.append(int(a["prediction"] == a["label"]) - int(b["prediction"] == b["label"]))
        discordant_left = sum(value == 1 for value in differences)
        discordant_right = sum(value == -1 for value in differences)
        paired.append({
            "left": left, "right": right, "bundles": len(differences),
            "bundles_excluded": len(indexed[left]) - len(differences),
            "accuracy_difference": sum(differences) / len(differences) if differences else None,
            "ci95": bootstrap_mean(differences) if differences else [None, None],
            "mcnemar": exact_mcnemar(discordant_left, discordant_right),
        })
    return {
        "bootstrap": {
            "method": "percentile, unstratified bundle resampling",
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": BOOTSTRAP_SEED,
            "confidence": 0.95,
            "paired_difference": "left minus right; identical bundle ids",
        },
        "macro_f1_definition": "Mean over all nine injected classes; absent-class F1 is zero",
        "groups": groups,
        "paired_accuracy_differences": paired,
    }
