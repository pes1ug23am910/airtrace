import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import httpx

from lab.manifest import write_manifest
from lab.scenarios import CLASS_IDS, bundle_id
from tests.triage.fixtures.build import AP, SSID, STATION, build_bundle, refresh_window
from triage import eval as evaluation
from triage.fake import ScriptedModel, answer, envelope, tool_call
from triage.freeze import freeze
from triage.llm import ChatClient
from triage.metrics import bootstrap_mean, compute_metrics, percentile


def row(bundle_id, label, prediction, group="rules", **changes):
    value = {
        "bundle_id": bundle_id, "label": label, "prediction": prediction,
        "group": group, "schema_failure": False, "error": None,
        "citations": {"valid": 1, "invalid": 0, "all_valid": True},
        "latency_ms": 10.0,
        "tokens": {"prompt": 10, "completion": 5, "total": 15},
        "cost_inr": 0.0,
    }
    value.update(changes)
    return value


def test_known_confusion_matrix_and_denominators():
    rows = [
        row("a", "ok", "ok"),
        row("b", "ok", "unknown", error="failed"),
        row("c", "wrong_passphrase", "ok", schema_failure=True,
            citations={"valid": 0, "invalid": 1, "all_valid": False}),
        row("d", "wrong_passphrase", "wrong_passphrase"),
    ]
    metrics = compute_metrics(rows)["groups"]["rules"]
    assert metrics["accuracy"] == 0.5
    assert metrics["per_class_recall"]["ok"] == 0.5
    assert metrics["per_class_recall"]["wrong_passphrase"] == 0.5
    assert metrics["per_class_recall"]["ap_full"] is None
    assert metrics["macro_f1"] == pytest.approx((0.5 + 2 / 3) / 9)
    assert metrics["confusion_matrix"]["ok"]["unknown"] == 1
    assert metrics["unknown_rate"] == 0.25
    assert metrics["schema_failure_rate"] == 0.25
    assert metrics["execution_error_rate"] == 0.25
    assert metrics["citation_all_valid_rate"] == 0.75
    assert metrics["invalid_citation_rate"] == 0.25


def test_bootstrap_determinism_and_paired_differences():
    rows = []
    for number in range(4):
        rows.append(row(str(number), "ok", "ok"))
        rows.append(row(str(number), "ok", "unknown", group="llm_raw/fake"))
    first = compute_metrics(rows)
    assert first == compute_metrics(rows)
    pair = first["paired_accuracy_differences"][0]
    assert pair["left"] == "llm_raw/fake"
    assert pair["accuracy_difference"] == -1
    assert pair["ci95"] == [-1, -1]
    assert first["bootstrap"]["resamples"] == 2000
    assert bootstrap_mean([0, 1, 0, 1]) == bootstrap_mean([0, 1, 0, 1])
    # Two Bernoulli observations yield means 0, 0.5, 1 with probabilities
    # 0.25, 0.5, 0.25. Their 2.5th/97.5th percentiles are exactly 0 and 1.
    assert bootstrap_mean([0, 1]) == [0, 1]
    assert percentile([0, 10], 0.95) == 9.5


@pytest.mark.parametrize("change", ["missing", "duplicate", "label"])
def test_invalid_pairing_rejected(change):
    rows = [row("a", "ok", "ok"), row("a", "ok", "unknown", "llm_raw/fake")]
    if change == "missing":
        rows.append(row("b", "ok", "unknown"))
    elif change == "duplicate":
        rows.append(dict(rows[0]))
    else:
        rows[1]["label"] = "wrong_passphrase"
    with pytest.raises(ValueError):
        compute_metrics(rows)


def test_unknown_usage_is_not_zero_and_empty_citations_are_unavailable():
    values = [row("a", "ok", "unknown", latency_ms=None,
                  tokens={"prompt": None, "completion": None, "total": None},
                  citations={"valid": 0, "invalid": 0, "all_valid": False})]
    metrics = compute_metrics(values)["groups"]["rules"]
    assert metrics["tokens_per_bundle"]["total"]["mean_per_bundle"] is None
    assert metrics["tokens_per_bundle"]["total"]["bundles_with_usage"] == 0
    assert metrics["invalid_citation_rate"] is None
    assert metrics["citation_all_valid_rate"] is None
    assert metrics["latency_ms"]["p95"] is None


def test_report_states_when_rules_win():
    metrics = compute_metrics([
        row("a", "ok", "ok"), row("a", "ok", "unknown", "llm_raw/fake"),
        row("a", "ok", "unknown", "llm_tools/fake"),
    ])
    report = evaluation.render_report(metrics, {
        "split": "dev", "run_id": "synthetic", "git_commit": "synthetic",
        "source_tree_sha256": "synthetic", "rules_placeholder": True,
    })
    assert "the rule baseline outperformed the LLM arms" in report
    assert "placeholder" in report
    assert "cannot support a held-out accuracy claim" in report
    assert "Confusion matrix for rules" in report
    assert "known-usage bundle (n)" in report


def test_invalid_configuration_error_does_not_expose_url_credentials(tmp_path):
    path = tmp_path / "models.json"
    path.write_text(json.dumps([{
        "name": "invalid", "base_url": "https://person:private-password@example.invalid/v1",
        "model": "scripted-model", "api_key_env": "", "supports_tools": True, "rpm": 1,
    }]), encoding="utf-8")
    with pytest.raises(ValueError) as caught:
        evaluation.load_models(path)
    assert "private-password" not in str(caught.value)


@pytest.fixture
def evaluation_inputs(tmp_path):
    dataset = tmp_path / "synthetic-dataset"
    build_bundle(dataset / bundle_id("ok", 1000), seed=1000)
    build_bundle(dataset / bundle_id("ok", 1100), seed=1100, split="test")
    write_manifest(dataset, 1000, "synthetic")
    root = tmp_path / "source"
    prompts = root / "triage" / "prompts"
    prompts.mkdir(parents=True)
    (root / "triage" / "rules.py").write_text("RULES = ()\n", encoding="utf-8")
    (prompts / "common.txt").write_text("synthetic fixture", encoding="utf-8")
    models = root / "models.json"
    models.write_text(json.dumps([{
        "name": "scripted", "base_url": "http://example.invalid/v1", "model": "scripted-model",
        "api_key_env": "", "supports_tools": True, "rpm": 1000000,
        "input_price_inr_per_million": 10.0, "output_price_inr_per_million": 20.0,
    }]), encoding="utf-8")
    binary = os.environ.get("AIRTRACE_BIN") or shutil.which("airtrace")
    if not binary:
        local = Path(__file__).resolve().parents[2] / ".local" / "airtrace.exe"
        if local.is_file():
            binary = str(local.resolve())
    return root, dataset, models, binary


def test_offline_synthetic_evaluation_writes_all_artifacts(evaluation_inputs, tmp_path, monkeypatch):
    root, dataset, models, binary = evaluation_inputs
    if not binary:
        pytest.skip("Build airtrace and set AIRTRACE_BIN for parser-backed evaluation")
    scripted = ScriptedModel([answer("ok"), tool_call(), answer("ok")])
    monkeypatch.setattr(evaluation, "ChatClient", lambda config: ChatClient(
        config, transport=scripted.transport, sleep=lambda seconds: None))
    out = tmp_path / "synthetic-output"
    metrics = evaluation.evaluate(dataset, "dev", ["rules", "llm_raw", "llm_tools"],
                                  models, out, binary=binary, root=root)
    assert set(metrics["groups"]) == {"rules", "llm_raw/scripted", "llm_tools/scripted"}
    assert metrics["groups"]["rules"]["unknown_rate"] == 1
    assert metrics["groups"]["llm_tools/scripted"]["accuracy"] == 1
    assert metrics["groups"]["llm_tools/scripted"]["tokens_per_bundle"]["total"]["total"] == 40
    assert len(metrics["paired_accuracy_differences"]) == 3
    rows = [json.loads(line) for line in (out / "per_bundle.jsonl").read_text(encoding="utf-8").splitlines()]
    traces = [json.loads(line) for line in (out / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 3
    assert len(traces) == 3
    assert all(record["resolved_model"] == "fake-resolved-version" for record in traces)
    assert all(row["source_tree_sha256"] for row in rows)
    assert (out / "metrics.json").is_file()
    assert (out / "report.md").is_file()
    assert "not Wi-Fi diagnosis results" in (out / "report.md").read_text(encoding="utf-8")
    rendered = json.dumps(scripted.requests)
    assert not any(identifier in rendered for identifier in (AP, STATION, SSID))


@pytest.mark.parametrize("failure", ["lab_failed", "timeout"])
def test_failed_bundle_is_counted_not_dropped(evaluation_inputs, tmp_path, monkeypatch, failure):
    root, dataset, models, binary = evaluation_inputs
    if failure == "lab_failed":
        if not binary:
            pytest.skip("Build airtrace and set AIRTRACE_BIN for parser-backed evaluation")
        path = dataset / bundle_id("ok", 1000) / "meta.json"
        meta = json.loads(path.read_text(encoding="utf-8"))
        meta.update(status="failed", error="synthetic setup failure")
        path.write_text(json.dumps(meta), encoding="utf-8")
        write_manifest(dataset, 1000, "synthetic")
    else:
        def timed_out(*args, **kwargs):
            raise subprocess.TimeoutExpired("synthetic", 30)
        monkeypatch.setattr(evaluation, "load_bundle", timed_out)
    out = tmp_path / "failed-output"
    metrics = evaluation.evaluate(dataset, "dev", ["rules"], models, out, binary=binary, root=root)
    group = metrics["groups"]["rules"]
    assert group["bundles"] == 1
    assert group["accuracy"] is None
    assert group["bundles_evaluated"] == 0
    assert group["bundles_excluded"] == 1
    assert group["excluded_reasons"] == {"quarantined" if failure == "lab_failed" else "load_error": 1}


def test_held_out_evaluation_refuses_without_freeze(evaluation_inputs, tmp_path):
    root, dataset, models, binary = evaluation_inputs
    out = tmp_path / "forbidden-output"
    with pytest.raises(ValueError, match="requires triage/FROZEN.json"):
        evaluation.evaluate(dataset, "test", ["rules"], models, out, binary=binary, root=root)
    assert not out.exists()


def test_matching_freeze_is_recorded_and_changed_source_refused(evaluation_inputs, tmp_path):
    root, dataset, models, binary = evaluation_inputs
    if not binary:
        pytest.skip("Build airtrace and set AIRTRACE_BIN for parser-backed evaluation")
    frozen = freeze(dataset, models, root=root)
    out = tmp_path / "held-out-synthetic"
    metrics = evaluation.evaluate(dataset, "test", ["rules"], models, out, binary=binary, root=root)
    assert metrics["provenance"]["frozen"] == frozen
    record = json.loads((out / "per_bundle.jsonl").read_text(encoding="utf-8"))
    assert record["frozen_hashes"] == frozen["hashes"]
    (root / "triage" / "rules.py").write_text("RULES = (changed,)\n", encoding="utf-8")
    refused = tmp_path / "changed-source"
    with pytest.raises(ValueError, match="Frozen inputs changed"):
        evaluation.evaluate(dataset, "test", ["rules"], models, refused, binary=binary, root=root)
    assert not refused.exists()


def test_f1_opaque_ids_reach_manifest_and_trace_without_labels(evaluation_inputs, tmp_path, monkeypatch):
    root, dataset, models, binary = evaluation_inputs
    assert binary, "Build airtrace and set AIRTRACE_BIN"
    manifest = json.loads((dataset / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["bundles"]:
        assert "label" not in entry
        for class_id in CLASS_IDS:
            assert class_id not in entry["id"]
            assert class_id not in entry["path"]
            assert class_id not in str(dataset / entry["path"])
    scripted = ScriptedModel([answer(), answer()])
    monkeypatch.setattr(evaluation, "ChatClient", lambda config: ChatClient(
        config, transport=scripted.transport, sleep=lambda seconds: None))
    observed_views = []
    original_run = evaluation.run_arm
    def inspect_arm(arm, view, **kwargs):
        observed_views.append(vars(view))
        return original_run(arm, view, **kwargs)
    monkeypatch.setattr(evaluation, "run_arm", inspect_arm)
    out = tmp_path / "identity-check"
    evaluation.evaluate(dataset, "dev", ["llm_raw", "llm_tools"], models, out,
                        binary=binary, root=root)
    traces = [json.loads(line) for line in (out / "trace.jsonl").read_text().splitlines()]
    assert all(trace["bundle_id"] == bundle_id("ok", 1000) for trace in traces)
    assert all(set(view) == {"frames", "logs", "stats", "name"} for view in observed_views)
    assert all("label" not in view and "manifest" not in view for view in observed_views)
    for trace in traces:
        assert not any(class_id in trace["bundle_id"] for class_id in CLASS_IDS)
    rows = [json.loads(line) for line in (out / "per_bundle.jsonl").read_text().splitlines()]
    assert all(record["bundle_id"] == bundle_id("ok", 1000) and record["label"] == "ok" for record in rows)


def test_f4_ambiguous_citation_rate_uses_all_cited_items():
    values = [row("a", "ok", "unknown", citations={
        "valid": 1, "invalid": 1, "all_valid": False, "ambiguous": 1}),
        row("b", "ok", "unknown", citations={
        "valid": 2, "invalid": 0, "all_valid": True, "ambiguous": 0})]
    metrics = compute_metrics(values)
    group = metrics["groups"]["rules"]
    assert group["ambiguous_citation_rate"] == 0.25
    assert group["citation_counts"]["ambiguous"] == 1
    report = evaluation.render_report(metrics, {
        "split": "dev", "run_id": "synthetic", "git_commit": "synthetic",
        "source_tree_sha256": "synthetic", "rules_placeholder": True})
    assert "Ambiguous citations" in report


def test_f8_unknown_cost_is_not_silently_counted_as_zero():
    values = [row("a", "ok", "unknown", cost_inr=0.004),
              row("b", "ok", "unknown", cost_inr=None)]
    cost = compute_metrics(values)["groups"]["rules"]["cost_inr"]
    assert cost == {"total": None, "known_subtotal": 0.004,
                    "mean_per_known_bundle": 0.004, "bundles_with_cost": 1}


def test_f8_cost_reaches_bundle_metrics_and_report(evaluation_inputs, tmp_path, monkeypatch):
    root, dataset, models, binary = evaluation_inputs
    assert binary, "Build airtrace and set AIRTRACE_BIN"
    scripted = ScriptedModel([answer()])
    monkeypatch.setattr(evaluation, "ChatClient", lambda config: ChatClient(
        config, transport=scripted.transport, sleep=lambda seconds: None))
    out = tmp_path / "cost-check"
    metrics = evaluation.evaluate(dataset, "dev", ["llm_raw"], models, out,
                                  binary=binary, root=root)
    trace = json.loads((out / "trace.jsonl").read_text())
    usage = trace["usage"]
    expected = (usage["prompt_tokens"] * 10 + usage["completion_tokens"] * 20) / 1_000_000
    record = json.loads((out / "per_bundle.jsonl").read_text())
    assert record["cost_inr"] == pytest.approx(expected)
    assert metrics["groups"]["llm_raw/scripted"]["cost_inr"]["total"] == pytest.approx(expected)
    assert "Cost INR" in (out / "report.md").read_text()
    assert f"{expected:.6f}" in (out / "report.md").read_text()


def test_r7_denominators_and_pairing_exclude_truncation_and_quarantine():
    values = [row("a", "ok", "ok"), row("a", "ok", "unknown", "llm_raw/fake"),
              row("b", "wrong_passphrase", "unknown", outcome="TRUNCATED"),
              row("b", "wrong_passphrase", "wrong_passphrase", "llm_raw/fake"),
              row("c", "ok", "unknown", excluded=True, exclusion_reason="quarantined"),
              row("c", "ok", "unknown", "llm_raw/fake", excluded=True, exclusion_reason="quarantined")]
    metrics = compute_metrics(values)
    group = metrics["groups"]["rules"]
    assert (group["bundles_evaluated"], group["bundles_excluded"], group["truncated"]) == (1, 2, 1)
    assert group["accuracy"] == 1
    assert group["schema_failures"] == 0
    assert group["accuracy_clopper_pearson_ci95"] == pytest.approx([0.025, 1])
    assert group["per_class_recall_bootstrap_ci95"]["ok"] == [1, 1]
    pair = metrics["paired_accuracy_differences"][0]
    assert (pair["bundles"], pair["bundles_excluded"]) == (1, 2)
    assert (pair["mcnemar"]["b"], pair["mcnemar"]["c"]) == (0, 1)
    assert pair["mcnemar"]["p_value"] == 1


def test_r7_report_does_not_claim_win_from_different_eligible_subsets():
    values = [row("a", "ok", "unknown"), row("b", "ok", "ok"), row("c", "ok", "ok"),
              row("a", "ok", "ok", "llm_raw/fake"), row("b", "ok", "unknown", "llm_raw/fake"),
              row("c", "ok", "unknown", "llm_raw/fake", outcome="TRUNCATED")]
    report = evaluation.render_report(compute_metrics(values), {
        "split": "dev", "run_id": "synthetic", "git_commit": "synthetic",
        "source_tree_sha256": "synthetic", "rules_placeholder": True})
    assert "the rule baseline outperformed the LLM arms" not in report
    assert "tied on their shared eligible bundles" in report


def test_r8_automatic_citations_do_not_inflate_resolves_rate():
    metrics = compute_metrics([
        row("a", "ok", "unknown", citations={"valid": 0, "invalid": 0, "auto": 1, "all_valid": False}),
        row("b", "ok", "ok", citations={"valid": 1, "invalid": 1, "ambiguous": 1, "all_valid": False})])
    group = metrics["groups"]["rules"]
    assert group["citation_resolves_rate"] == 0.5
    assert group["citation_ambiguous_rate"] == 0.5
    assert group["citation_counts"]["auto_excluded"] == 1
    assert group["citation_counts"]["bundles_with_model_citations"] == 1


@pytest.mark.parametrize("view", ["client", "full"])
def test_r5_evaluation_records_and_restricts_view(evaluation_inputs, tmp_path, monkeypatch, view):
    root, dataset, models, binary = evaluation_inputs
    scripted = ScriptedModel([answer()])
    monkeypatch.setattr(evaluation, "ChatClient", lambda config: ChatClient(config, transport=scripted.transport))
    out = tmp_path / "view-output"
    metrics = evaluation.evaluate(dataset, "dev", ["llm_raw"], models, out, binary=binary, root=root, view=view)
    record = json.loads((out / "per_bundle.jsonl").read_text())
    trace = json.loads((out / "trace.jsonl").read_text())
    assert record["view"] == trace["view"] == metrics["provenance"]["view"] == view
    user_input = scripted.requests[0]["messages"][1]["content"]
    assert ("hostapd:\n" in user_input) == (view == "full")
    assert ("dhcp_server:\n" in user_input) == (view == "full")
    assert (out / "audit_sample.csv").is_file()


def test_r6_truncated_evaluation_is_excluded_not_schema_failure(evaluation_inputs, tmp_path, monkeypatch):
    root, dataset, models, binary = evaluation_inputs
    response = envelope(answer())
    response["choices"][0]["finish_reason"] = "length"
    scripted = ScriptedModel([httpx.Response(200, json=response)])
    monkeypatch.setattr(evaluation, "ChatClient", lambda config: ChatClient(config, transport=scripted.transport))
    out = tmp_path / "truncated-output"
    metrics = evaluation.evaluate(dataset, "dev", ["llm_raw"], models, out, binary=binary, root=root)
    group = metrics["groups"]["llm_raw/scripted"]
    assert group["accuracy"] is None
    assert group["truncated"] == 1 and group["schema_failures"] == 0
    assert group["tokens_per_bundle"]["total"]["total"] == 20
    record = json.loads((out / "per_bundle.jsonl").read_text())
    assert record["outcome"] == "TRUNCATED" and record["finish_reason"] == "length"
    assert record["citations"]["auto"] == 1
    assert len(scripted.requests) == 1
    report = (out / "report.md").read_text(encoding="utf-8")
    assert report.startswith("Paired difference with CI:")
    assert "TRUNCATED: 1" in report


def test_r6_preflight_checks_all_bundles_before_client_creation(evaluation_inputs, tmp_path, monkeypatch):
    root, dataset, models, binary = evaluation_inputs
    later = build_bundle(dataset / bundle_id("ok", 1001), seed=1001)
    (later / "wpa_supplicant.log").write_text("long log line\n" * 20000, encoding="utf-8")
    refresh_window(later)
    write_manifest(dataset, 1000, "synthetic")
    entries = json.loads(models.read_text())
    entries[0]["context_length"] = 20000
    models.write_text(json.dumps(entries))
    def forbidden_client(config):
        pytest.fail("preflight must finish before constructing any client")
    monkeypatch.setattr(evaluation, "ChatClient", forbidden_client)
    out = tmp_path / "context-refused"
    with pytest.raises(ValueError, match="context_length"):
        evaluation.evaluate(dataset, "dev", ["llm_raw"], models, out, binary=binary, root=root)
    assert not out.exists()


@pytest.mark.parametrize("arm", ["rules", "llm_raw"])
def test_r9_quarantined_bundle_never_reaches_an_arm(evaluation_inputs, tmp_path, monkeypatch, arm):
    root, dataset, models, binary = evaluation_inputs
    path = dataset / bundle_id("ok", 1000) / "meta.json"
    meta = json.loads(path.read_text())
    meta["injection_verified"] = False
    path.write_text(json.dumps(meta))
    write_manifest(dataset, 1000, "synthetic")
    monkeypatch.setattr(evaluation, "run_arm", lambda *args, **kwargs: pytest.fail("quarantined input reached an arm"))
    monkeypatch.setattr(evaluation, "ChatClient", lambda *args, **kwargs: pytest.fail("quarantined input constructed a client"))
    out = tmp_path / "quarantine-output"
    metrics = evaluation.evaluate(dataset, "dev", [arm], models, out, binary=binary, root=root)
    group = metrics["groups"][arm if arm == "rules" else arm + "/scripted"]
    assert group["bundles_excluded"] == 1 and group["accuracy"] is None
    record = json.loads((out / "per_bundle.jsonl").read_text())
    assert record["label"] == "ok" and record["quarantine_reasons"] == ["injection_unverified"]
