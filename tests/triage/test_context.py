"""Offline regressions for observation views, output limits and context planning."""

import json
from pathlib import Path

import httpx
import pytest

from triage.arms import preflight, raw_logs, run_arm
from triage.data import View
from triage.fake import ScriptedModel, answer, envelope, malformed, tool_call
from triage.llm import ChatClient, ContextLimitError, ModelConfig, estimate_prompt_tokens
from triage.trace import MemoryTrace


def observations(name="client"):
    return View({1: {"frame": 1, "type": "management"}},
                {"hostapd": ["AP_ONLY_MARKER authenticated"],
                 "wpa_supplicant": ["STA_ONLY_MARKER connection failed"],
                 "dhcp_server": ["SERVER_ONLY_MARKER lease issued"],
                 "dhcp_client": ["CLIENT_ONLY_MARKER lease acquired"]},
                "Frames: 1 parsed: 1 errors: 0", name=name)


def configuration(**changes):
    values = {"name": "offline", "base_url": "http://localhost/v1",
              "model": "scripted", "supports_tools": True, "rpm": 1000000}
    values.update(changes)
    return ModelConfig(**values)


def test_r5_raw_inputs_and_trace_share_the_selected_view():
    for name in ("client", "full"):
        fake = ScriptedModel([answer(source="wpa_supplicant",
                                     quote="STA_ONLY_MARKER connection failed")])
        trace = MemoryTrace()
        with ChatClient(configuration(), transport=fake.transport,
                        sleep=lambda _: None) as client:
            result = run_arm("llm_raw", observations(name), client=client, trace=trace)
        rendered = json.dumps(fake.requests)
        assert "STA_ONLY_MARKER" in rendered and "CLIENT_ONLY_MARKER" in rendered
        assert ("AP_ONLY_MARKER" in rendered) == (name == "full")
        assert ("SERVER_ONLY_MARKER" in rendered) == (name == "full")
        assert set(result.trimming) == set(observations(name).allowed_sources)
        assert trace.records[0]["view"] == name


def test_r5_raw_budget_is_shared_only_among_visible_sources():
    _, details = raw_logs(observations(), 48000)
    assert set(details) == {"wpa_supplicant", "dhcp_client"}
    assert all(row["allocated_chars"] == 24000 for row in details.values())


@pytest.mark.parametrize("valid_json", [True, False])
def test_r6_length_finish_is_truncated_without_repair_or_schema_failure(valid_json):
    response = envelope(answer() if valid_json else malformed())
    response["choices"][0]["finish_reason"] = "length"
    fake = ScriptedModel([httpx.Response(200, json=response)])
    trace = MemoryTrace()
    with ChatClient(configuration(), transport=fake.transport) as client:
        result = run_arm("llm_raw", observations(), client=client, trace=trace)
    assert result.outcome == "TRUNCATED"
    assert result.finish_reason == "length"
    assert not result.schema_failure
    assert len(fake.requests) == 1
    assert trace.records[0]["validation_stage"] == "truncated"
    assert all(item.auto for item in result.diagnosis.evidence)


def test_r6_preflight_refuses_oversize_input_before_any_request():
    view = observations()
    view.logs["wpa_supplicant"] = ["long source observation " * 30 for _ in range(100)]
    fake = ScriptedModel([answer()])
    with ChatClient(configuration(context_length=32768), transport=fake.transport) as client:
        with pytest.raises(ContextLimitError, match="context_length"):
            run_arm("llm_raw", view, client=client)
    assert fake.requests == []


def test_r6_preflight_reserves_output_and_a_bounded_tool_history():
    config = configuration(context_length=32768)
    plan = preflight("llm_tools", observations(), config)
    assert plan["largest_prompt_tokens_estimate"] + config.max_tokens <= 32768
    assert 0 < plan["tool_history_budget"] <= 16000
    with pytest.raises(ContextLimitError):
        preflight("llm_raw", observations(), configuration(context_length=8192))


def test_r6_every_request_has_a_context_guard_even_outside_run_arm():
    fake = ScriptedModel([answer()])
    with ChatClient(configuration(context_length=8192), transport=fake.transport) as client:
        with pytest.raises(ContextLimitError):
            client.complete([{"role": "user", "content": "x" * 8192}])
    assert not fake.requests


def test_r6_oversized_tool_output_is_explicitly_omitted_and_loop_stops():
    view = observations()
    view.logs["wpa_supplicant"] = ["many diagnostics " * 70 for _ in range(80)]
    fake = ScriptedModel([tool_call("read_log", {"source": "wpa_supplicant",
                                               "start": 1, "end": 80}),
                          answer(source="frame", quote='"type": "management"')])
    trace = MemoryTrace()
    with ChatClient(configuration(context_length=32768), transport=fake.transport,
                    sleep=lambda _: None) as client:
        result = run_arm("llm_tools", view, client=client, trace=trace)
    assert len(fake.requests) == 2
    assert "tools" not in fake.requests[1]
    assert "omitted because the context" in json.dumps(fake.requests[1])
    assert result.trimming["tool_context"][0]["omitted_chars"] > 16000
    assert result.outcome == "DIAGNOSED"
    for request in fake.requests:
        assert estimate_prompt_tokens(request["messages"], request.get("tools")) + 4096 <= 32768


@pytest.mark.parametrize("fraction,expected", [(0.979, False), (0.98, True), (1.0, True)])
def test_r6_usage_near_context_limit_flags_suspected_truncation(fraction, expected):
    response = envelope(answer())
    response["usage"]["prompt_tokens"] = int(50000 * fraction)
    fake = ScriptedModel([httpx.Response(200, json=response)])
    trace = MemoryTrace()
    with ChatClient(configuration(context_length=50000), transport=fake.transport) as client:
        result = run_arm("llm_raw", observations(), client=client, trace=trace)
    assert result.truncation_suspected == expected
    assert trace.records[0]["truncation_suspected"] == expected
    assert result.outcome == "DIAGNOSED"


def test_r6_committed_output_and_local_context_limits():
    configs = {item["name"]: ModelConfig.model_validate(item) for item in
               json.loads((Path(__file__).parents[2] / "models.json").read_text())["models"]}
    assert configuration().max_tokens == 4096
    assert configs["jarvislabs-gpt-oss-120b"].max_tokens == 8192
    assert configs["ollama-qwen3.5-9b"].context_length == 32768


def test_r8_model_cannot_exclude_its_own_citations_by_claiming_auto():
    message = answer(source="frame", quote='"type": "management"')
    diagnosis = json.loads(message["content"])
    diagnosis["evidence"][0]["auto"] = True
    message["content"] = json.dumps(diagnosis)
    fake = ScriptedModel([message])
    with ChatClient(configuration(), transport=fake.transport) as client:
        result = run_arm("llm_tools", observations(), client=client)
    assert result.outcome == "DIAGNOSED"
    assert not result.diagnosis.evidence[0].auto


def test_r8_rules_citations_are_automatic_even_for_a_custom_rule(monkeypatch):
    from triage.schema import Diagnosis

    diagnosis = Diagnosis.model_validate_json(
        answer(source="frame", quote='"type": "management"')["content"])
    assert not diagnosis.evidence[0].auto
    monkeypatch.setattr("triage.rules.diagnose", lambda view: diagnosis)
    result = run_arm("rules", observations())
    assert result.diagnosis.evidence[0].auto


@pytest.mark.parametrize("location", ["content", "provider_field"])
def test_r6_large_assistant_or_provider_fields_cannot_exceed_preflight_plan(location):
    message = tool_call()
    if location == "content":
        message["content"] = "a" * 40000
    else:
        message["tool_calls"][0]["extra_content"] = {
            "google": {"thought_signature": "opaque" * 7000}}
    fake = ScriptedModel([message])
    trace = MemoryTrace()
    with ChatClient(configuration(), transport=fake.transport) as client:
        result = run_arm("llm_tools", observations(), client=client, trace=trace)
    assert len(fake.requests) == 1
    assert result.outcome == "CONTEXT_REJECTED"
    assert not result.schema_failure
    assert result.context_plan["rejected_prompt_tokens_estimate"] > result.context_plan[
        "largest_prompt_tokens_estimate"]
    retained = json.loads(trace.records[0]["raw_response_body"])["choices"][0]["message"]
    assert retained == message
