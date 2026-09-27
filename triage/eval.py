"""Evaluate injected labels without exposing them to diagnosis methods."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import time

from triage.arms import preflight, run_arm
from triage.audit import write_audit_sample
from triage.citations import check
from triage.data import load_bundle
from triage.freeze import ROOT, canonical_hash, git_commit, sha256, source_hashes
from triage.freeze import verified_manifest, verify_frozen
from triage.freeze import DEFAULT_RAW_CHAR_BUDGET, evaluation_settings
from triage.llm import ChatClient, ModelConfig
from triage.metrics import CLASS_IDS, compute_metrics
from triage.redact import redact_bundle
from triage.rules import PLACEHOLDER
from triage.trace import TraceWriter
from pydantic import ValidationError


ARM_IDS = ("rules", "llm_raw", "llm_tools")


def load_models(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = value["models"] if isinstance(value, dict) else value
    if not isinstance(entries, list):
        raise ValueError("models.json must be a list or an object containing a models list")
    models = []
    for index, entry in enumerate(entries):
        try:
            models.append(ModelConfig.model_validate(entry))
        except ValidationError:
            # Validation details can contain rejected credentials in a URL.
            raise ValueError(f"Invalid model configuration at index {index}") from None
    if len({model.name for model in models}) != len(models):
        raise ValueError("Model names must be unique")
    return models


def environment():
    versions = {}
    for package in ("pytest", "pydantic", "httpx"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "packages": versions,
        "logical_cpus": os.cpu_count(),
        "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
        "load_note": "Other work on this host may affect latency; load averages are unavailable on Windows.",
    }


def _format(value):
    return "unavailable" if value is None else f"{value:.3f}"


def _interval(values):
    return "(" + ", ".join(_format(value) for value in values) + ")"


def render_report(metrics, provenance):
    comparisons = metrics["paired_accuracy_differences"]
    paired_summary = "; ".join(
        f"{pair['left']} minus {pair['right']}: {_format(pair['accuracy_difference'])} "
        f"{_interval(pair['ci95'])}, n={pair['bundles']}" for pair in comparisons)
    lines = [
        "Paired difference with CI: " + (paired_summary or "unavailable (one arm/model group)."), "",
        f"Split: {provenance['split']}. Run: {provenance['run_id']}.",
        f"Observation view: {provenance.get('view', 'client')} "
        + ("(primary)." if provenance.get("view", "client") == "client" else "(supplementary)."),
        f"Git commit: `{provenance['git_commit']}`. Working-source SHA-256: `{provenance['source_tree_sha256']}`.",
        "", "| Arm / model | Evaluated / total | Accuracy (bootstrap 95% CI; Clopper–Pearson 95% CI) | Macro-F1 | Unknown | Schema failure | Citation all-valid | Citation resolves | Ambiguous citations | p50 / p95 ms | Tokens / known-usage bundle (n) | Cost INR (known subtotal; n) |",
        "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |",
    ]
    for name, group in metrics["groups"].items():
        interval = group["accuracy_ci95"]
        latency = group["latency_ms"]
        cost = group["cost_inr"]
        cost_text = "unavailable" if cost["known_subtotal"] is None else f"{cost['known_subtotal']:.6f}"
        lines.append(
            f"| {name} | {group['bundles_evaluated']} / {group['bundles']} | {_format(group['accuracy'])} {_interval(interval)}; "
            f"{_interval(group['accuracy_clopper_pearson_ci95'])} "
            f"| {_format(group['macro_f1'])} | {_format(group['unknown_rate'])} | {_format(group['schema_failure_rate'])} "
            f"| {_format(group['citation_all_valid_rate'])} | {_format(group['citation_resolves_rate'])} "
            f"| {_format(group['citation_ambiguous_rate'])} "
            f"| {_format(latency['p50'])} / {_format(latency['p95'])} "
            f"| {_format(group['tokens_per_bundle']['total']['mean_per_bundle'])} "
            f"({group['tokens_per_bundle']['total']['bundles_with_usage']}) "
            f"| {cost_text} ({cost['bundles_with_cost']}/{group['bundles']}) |"
        )
    lines.extend(["", "| Arm / model | Excluded | Reasons | TRUNCATED | Schema failures | Suspected truncation |",
                  "| --- | ---: | --- | ---: | ---: | ---: |"])
    for name, group in metrics["groups"].items():
        reasons = ", ".join(f"{reason}: {count}" for reason, count in group["excluded_reasons"].items()) or "none"
        lines.append(f"| {name} | {group['bundles_excluded']} | {reasons} | {group['truncated']} "
                     f"| {group['schema_failures']} | {group['truncation_suspected']} |")
    lines.extend(["", "| Class recall (bootstrap 95% CI; Clopper–Pearson 95% CI; n) | " + " | ".join(metrics["groups"]) + " |",
                  "| --- | " + " | ".join("---:" for _ in metrics["groups"]) + " |"])
    for label in CLASS_IDS:
        values = [f"{_format(group['per_class_recall'][label])} "
                  f"{_interval(group['per_class_recall_bootstrap_ci95'][label])}; "
                  f"{_interval(group['per_class_recall_clopper_pearson_ci95'][label])}; "
                  f"n={group['per_class_support'][label]}" for group in metrics["groups"].values()]
        lines.append("| " + label + " | " + " | ".join(values) + " |")
    columns = CLASS_IDS + ("unknown",)
    for name, group in metrics["groups"].items():
        lines.extend([
            "", f"Confusion matrix for {name}; rows are injected classes, columns are predictions.", "",
            "| Injected class | " + " | ".join(columns) + " |",
            "| --- | " + " | ".join("---:" for _ in columns) + " |",
        ])
        for label in CLASS_IDS:
            counts = [str(group["confusion_matrix"][label][column]) for column in columns]
            lines.append("| " + label + " | " + " | ".join(counts) + " |")
    lines.extend(["", "| Paired comparison (left minus right) | Evaluated / excluded | Accuracy difference | 95% CI | b / c | Exact McNemar p |",
                  "| --- | ---: | ---: | --- | --- | ---: |"])
    for pair in metrics["paired_accuracy_differences"]:
        lines.append(
            f"| {pair['left']} minus {pair['right']} | {pair['bundles']} / {pair['bundles_excluded']} "
            f"| {_format(pair['accuracy_difference'])} | {_interval(pair['ci95'])} "
            f"| {pair['mcnemar']['b']} / {pair['mcnemar']['c']} | {_format(pair['mcnemar']['p_value'])} |"
        )
    lines.extend(["", "## What this shows", ""])
    if provenance.get("synthetic_fixture_data"):
        lines.append("This run uses synthetic test fixtures. Its numbers validate evaluation plumbing and are not Wi-Fi diagnosis results.")
    available = {name: group for name, group in metrics["groups"].items() if group["accuracy"] is not None}
    if available:
        best_accuracy = max(group["accuracy"] for group in available.values())
        best = [name for name, group in available.items() if group["accuracy"] == best_accuracy]
        lines.append("The highest observed accuracy was " + f"{best_accuracy:.3f} for " + ", ".join(best)
                     + ". These marginal scores may use different eligible subsets; paired comparisons use the shared subset.")
    else:
        lines.append("No bundles were eligible for accuracy scoring.")
    llm_names = [name for name in metrics["groups"] if name.startswith("llm_")]
    rule_differences = []
    for pair in comparisons:
        if pair["accuracy_difference"] is None:
            continue
        if pair["left"] == "rules":
            rule_differences.append(pair["accuracy_difference"])
        elif pair["right"] == "rules":
            rule_differences.append(-pair["accuracy_difference"])
    complete_comparison = bool(llm_names) and len(rule_differences) == len(llm_names)
    if complete_comparison and all(difference > 0 for difference in rule_differences):
        lines.append("the rule baseline outperformed the LLM arms")
        lines.append("This describes the paired point estimates; it does not assert a statistically reliable advantage.")
    elif complete_comparison and all(difference == 0 for difference in rule_differences):
        lines.append("The rule baseline and all evaluated LLM arms tied on their shared eligible bundles.")
    if provenance["rules_placeholder"]:
        lines.append("The rule baseline is still a placeholder that always returns unknown; it is not a developed rule system.")
    lines.append("Quarantined captures, load failures and TRUNCATED/CONTEXT_REJECTED outcomes are excluded with reasons above. "
                 "Schema failures remain unknown in the evaluated denominator. Paired comparisons use only bundles eligible in both groups.")
    lines.append("audit_sample.csv contains a fixed-seed sample of up to three diagnoses per class and arm for manual citation-support review.")
    lines.extend([
        "", "## What this does not show", "",
        "These labels describe the injected class, not a diagnosis independently established from the observed packets. "
        "The simulation does not establish performance on real RF propagation, physical drivers, firmware, or other kernel and hostapd versions.",
        "The 95% intervals use 2,000 fixed-seed, unstratified resamples of bundles. "
        "They reflect sampling uncertainty within this dataset, not repeated model draws or independent hardware environments. "
        "A higher point estimate alone does not establish a reliable difference; inspect the paired interval.",
        "Clopper–Pearson intervals invert binomial tails. Exact McNemar p-values use the two discordant counts "
        "(b: only left correct; c: only right correct), without a multiple-comparison correction. "
        "These calculations do not remove dependence between simulated runs on one host.",
        "Citation checking establishes that quoted text exists, not that it supports the causal conclusion. "
        "All-four-message EAPOL observation does not prove a valid password, successful key exchange, or a DHCP lease.",
        "Macro-F1 averages the nine injected classes; an absent class contributes zero and its recall is unavailable. "
        "Citation resolves rate counts matching model citations divided by all model citations in evaluated rows; automatic fallback/rule citations are excluded. "
        "Citation all-valid rate uses only evaluated rows with at least one model citation. "
        "Ambiguous-citation rate is items whose quote occurs in more than three source lines or frames, divided by all cited items; ambiguity does not itself invalidate a quotation. "
        "Unavailable token usage is not counted as zero. Cost, tokens and latency include truncated attempts. Latency includes method execution and retries, excludes capture parsing, "
        "and depends on concurrent host load and provider conditions.",
        "Costs are INR estimates from configured rates and returned usage, not invoices. Cached input is billed at its configured cached rate when its count is provided; absent cached counts are recorded as an assumption of zero. "
        "Reasoning tokens already included in completion totals are not added again. Null rates, missing usage, or an unpriced cached portion yield unavailable cost. "
        "The table shows only known subtotals and their bundle counts; a complete total is unavailable if any bundle cost is unknown. Free-tier availability, taxes, server hardware and energy costs are not inferred.",
    ])
    if provenance["split"] == "dev":
        lines.append("This is a development-split evaluation and cannot support a held-out accuracy claim.")
    return "\n".join(lines) + "\n"


def evaluate(dataset, split, arms, models_path, out, *, binary=None, root=ROOT,
             raw_char_budget=DEFAULT_RAW_CHAR_BUDGET, view="client"):
    dataset = Path(dataset)
    out = Path(out)
    root = Path(root)
    if split not in ("dev", "test"):
        raise ValueError("split must be dev or test")
    if type(raw_char_budget) is not int or raw_char_budget < 300:
        raise ValueError("raw character budget must be an integer of at least 300")
    settings = evaluation_settings(models_path, view=view, raw_char_budget=raw_char_budget)
    if not arms or len(arms) != len(set(arms)) or any(arm not in ARM_IDS for arm in arms):
        raise ValueError("Select unique arms from rules, llm_raw, llm_tools")
    manifest = verified_manifest(dataset)
    entries = [entry for entry in manifest["bundles"] if entry["split"] == split]
    if not entries:
        raise ValueError("No bundles in requested split")
    frozen = verify_frozen(dataset, models_path, root=root,
                           raw_char_budget=raw_char_budget, view=view) if split == "test" else None
    need_models = any(arm != "rules" for arm in arms)
    models = load_models(models_path) if need_models else []
    if need_models and not models:
        raise ValueError("LLM arms require at least one explicit model configuration")
    if "llm_tools" in arms and any(not model.supports_tools for model in models):
        raise ValueError("llm_tools requires supports_tools=true for every selected model")
    groups = []
    for arm in arms:
        if arm == "rules":
            groups.append((arm, None))
        else:
            groups.extend((arm, model) for model in models)
    hashes = source_hashes(root)
    provenance = {
        "run_id": out.name,
        "split": split,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_commit(root),
        "source_tree_sha256": canonical_hash(hashes),
        "source_file_sha256": hashes,
        "manifest_sha256": sha256(dataset / "manifest.json"),
        "synthetic_fixture_data": manifest.get("generator_commit") == "synthetic",
        "frozen": frozen,
        "models_sha256": sha256(models_path) if models_path and Path(models_path).is_file() else None,
        "rules_placeholder": PLACEHOLDER,
        "redaction": "HMAC-SHA256, fresh per-evaluation key shared across arms; key not persisted",
        "environment_start": environment(),
        "raw_char_budget": raw_char_budget,
        "view": view, "evaluation_settings": settings,
        "evaluation_settings_sha256": canonical_hash(settings),
    }
    # Check every eligible input before constructing a client. A later oversized
    # bundle must not reject a run after earlier bundles have already incurred cost.
    prepared = []
    redaction_key = secrets.token_bytes(32)
    for entry in entries:
        metadata = json.loads((dataset / entry["path"] / "meta.json").read_text(encoding="utf-8"))
        observation = None
        load_error = None
        exclusion = "quarantined" if entry["quarantined"] else None
        if not exclusion:
            try:
                bundle = load_bundle(dataset / entry["path"], binary=binary)
                if not bundle.frames:
                    raise ValueError("Bundle contains no frames")
                observation = redact_bundle(bundle, redaction_key, view=view)
            except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as error:
                load_error = type(error).__name__ + ": bundle loading failed"
                exclusion = "load_error"
        if observation is not None:
            for arm, model in groups:
                if model is not None:
                    preflight(arm, observation, model, raw_char_budget)
        prepared.append((entry, metadata, observation, exclusion, load_error))
    out.mkdir(parents=True, exist_ok=False)
    trace = TraceWriter(out / "trace.jsonl")
    rows = []
    with ExitStack() as stack:
        active_models = models if any(item[2] is not None for item in prepared) else []
        clients = {model.name: stack.enter_context(ChatClient(model)) for model in active_models}
        with (out / "per_bundle.jsonl").open("x", encoding="utf-8") as handle:
            for entry, metadata, observation, exclusion, load_error in prepared:
                for arm, model in groups:
                    row = {
                        "run_id": out.name, "bundle_id": entry["id"], "split": split,
                        "label": metadata["label"], "seed": entry["seed"],
                        "arm": arm, "model_name": model.name if model else None,
                        "requested_model": model.model if model else None,
                        "group": arm + ("/" + model.name if model else ""),
                        "prediction": "unknown", "diagnosis": None,
                        "schema_failure": False, "view": view,
                        "excluded": exclusion is not None, "exclusion_reason": exclusion,
                        "quarantine_reasons": entry["quarantine_reasons"],
                        "outcome": "EXCLUDED" if exclusion else "ERROR",
                        "finish_reason": None, "truncation_suspected": False, "context_plan": {},
                        "citations": {"valid": 0, "invalid": 0, "all_valid": False,
                                      "ambiguous": 0, "eligible": 0, "auto": 0, "items": []},
                        "latency_ms": None, "tokens": {"prompt": None, "completion": None, "total": None},
                        "cost_inr": None, "pricing": {},
                        "raw_char_budget": raw_char_budget,
                        "trimming": {}, "prompt_hashes": {}, "error": load_error,
                        "git_commit": provenance["git_commit"],
                        "source_tree_sha256": provenance["source_tree_sha256"],
                        "manifest_sha256": provenance["manifest_sha256"],
                        "models_sha256": provenance["models_sha256"],
                        "frozen_hashes": frozen["hashes"] if frozen else None,
                        "evaluation_settings": settings,
                        "evaluation_settings_sha256": provenance["evaluation_settings_sha256"],
                    }
                    if observation is not None:
                        start = time.perf_counter()
                        try:
                            result = run_arm(
                                arm, observation, client=clients[model.name] if model else None,
                                trace=trace, run_id=out.name, bundle_id=entry["id"],
                                raw_char_budget=raw_char_budget,
                            )
                            row.update(
                                prediction=result.diagnosis.root_cause,
                                diagnosis=result.diagnosis.model_dump(),
                                schema_failure=result.schema_failure,
                                citations=check(result.diagnosis, observation),
                                latency_ms=result.latency_ms, tokens=result.tokens,
                                cost_inr=result.cost_inr, pricing=result.pricing,
                                trimming=result.trimming, prompt_hashes=result.prompt_hashes,
                                error=result.error,
                                outcome=result.outcome, finish_reason=result.finish_reason,
                                truncation_suspected=result.truncation_suspected,
                                context_plan=result.context_plan,
                            )
                            if result.outcome in ("TRUNCATED", "CONTEXT_REJECTED"):
                                row["excluded"] = True
                                row["exclusion_reason"] = result.outcome
                        except Exception as error:
                            row["error"] = type(error).__name__ + ": method execution failed"
                            row["latency_ms"] = (time.perf_counter() - start) * 1000
                    rows.append(row)
                    handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
                    handle.flush()
    verified_manifest(dataset)
    if sha256(dataset / "manifest.json") != provenance["manifest_sha256"]:
        raise ValueError("Dataset manifest changed during evaluation; results are incomplete")
    if canonical_hash(source_hashes(root)) != provenance["source_tree_sha256"]:
        raise ValueError("Source files changed during evaluation; results are incomplete")
    if provenance["models_sha256"] is not None and sha256(models_path) != provenance["models_sha256"]:
        raise ValueError("Model configuration changed during evaluation; results are incomplete")
    if split == "test":
        verify_frozen(dataset, models_path, root=root, raw_char_budget=raw_char_budget, view=view)
    provenance["ended_utc"] = datetime.now(timezone.utc).isoformat()
    provenance["environment_end"] = environment()
    metrics = compute_metrics(rows)
    metrics["provenance"] = provenance
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "report.md").write_text(render_report(metrics, provenance), encoding="utf-8")
    write_audit_sample(rows, out / "audit_sample.csv")
    return metrics


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--split", choices=("dev", "test"), required=True)
    parser.add_argument("--arms", nargs="+", default=["rules"])
    parser.add_argument("--models", type=Path, default=ROOT / "models.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--airtrace", type=Path)
    parser.add_argument("--raw-char-budget", type=int, default=DEFAULT_RAW_CHAR_BUDGET)
    parser.add_argument("--view", choices=("client", "full"), default="client")
    args = parser.parse_args(argv)
    arms = [arm for group in args.arms for arm in group.split(",")]
    try:
        metrics = evaluate(args.dataset, args.split, arms, args.models, args.out,
                           binary=args.airtrace, raw_char_budget=args.raw_char_budget, view=args.view)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, str(error) + "\n")
    print(f"Wrote {len(metrics['groups'])} evaluation groups to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
