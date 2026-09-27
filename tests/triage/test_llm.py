import json
from pathlib import Path

import httpx
import pytest

from triage.arms import raw_logs, run_arm
from triage.citations import check
from triage.data import Bundle, View
from triage.fake import ScriptedModel, answer, envelope, fabricated, malformed, tool_call
from triage.llm import ChatClient, ModelConfig, estimate_cost
from triage.redact import redact_bundle
from triage.trace import MemoryTrace, TraceWriter, fingerprint


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def config(**changes):
    values = {"name": "fake", "base_url": "http://localhost:11434/v1",
              "model": "explicit-test-model", "api_key_env": "",
              "supports_tools": True, "rpm": 60}
    values.update(changes)
    return ModelConfig(**values)


def client_for(fake, **changes):
    clock = Clock()
    client = ChatClient(config(**changes), transport=fake.transport,
                        sleep=clock.sleep, monotonic=clock.monotonic)
    return client, clock


@pytest.fixture
def view():
    return View(
        frames={1: {"frame": 1, "subtype": "beacon", "ssid": "ssid-01234567",
                    "addrs": ["02:11:22:33:44:55"], "status_code": None,
                    "reason_code": None, "eapol_msg": None}},
        logs={"hostapd": ["wlan0: AP-ENABLED"],
              "wpa_supplicant": ["scanning"], "dhcp_server": ["DHCP server ready"],
              "dhcp_client": ["DHCPDISCOVER"]},
        stats="Frames: 1 parsed: 1 errors: 0", name="full",
    )


def test_raw_arm_valid_and_no_tools(view):
    fake = ScriptedModel([answer()])
    client, _ = client_for(fake)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_raw", view, client=client, trace=trace)
    assert result.diagnosis.root_cause == "unknown"
    assert not result.schema_failure
    assert result.tokens == {"prompt": 13, "completion": 7, "total": 20}
    assert "tools" not in fake.requests[0]
    assert "1: wlan0: AP-ENABLED" in fake.requests[0]["messages"][1]["content"]
    assert check(result.diagnosis, view)["all_valid"]
    assert trace.records[0]["validation_passed"]


def test_tools_then_final_diagnosis(view):
    fake = ScriptedModel([tool_call(), answer()])
    client, _ = client_for(fake)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_tools", view, client=client, trace=trace)
    assert not result.schema_failure
    assert len(fake.requests) == 2
    assert len(fake.requests[0]["tools"]) == 6
    assert fake.requests[1]["messages"][-1]["role"] == "tool"
    assert "Frames: 1" in fake.requests[1]["messages"][-1]["content"]
    assert trace.records[0]["validation_stage"] == "tool_calls"


def test_one_repair(view):
    fake = ScriptedModel([malformed(), answer()])
    client, _ = client_for(fake)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_raw", view, client=client, trace=trace)
    assert not result.schema_failure
    assert len(fake.requests) == 2
    assert "Validation failed" in fake.requests[1]["messages"][-1]["content"]
    assert not trace.records[0]["validation_passed"]
    assert trace.records[1]["validation_passed"]


def test_second_invalid_answer_is_schema_failure(view):
    fake = ScriptedModel([malformed(), malformed()])
    client, _ = client_for(fake)
    with client:
        result = run_arm("llm_raw", view, client=client)
    assert result.schema_failure
    assert result.diagnosis.root_cause == "unknown"
    assert len(fake.requests) == 2
    assert result.outcome == "SCHEMA_FAILURE"
    assert check(result.diagnosis, view)["eligible"] == 0
    assert all(item.auto for item in result.diagnosis.evidence)


def test_raw_arm_rejects_frame_citations(view):
    fake = ScriptedModel([answer(source="frame", quote="beacon"), answer()])
    client, _ = client_for(fake)
    with client:
        result = run_arm("llm_raw", view, client=client)
    assert len(fake.requests) == 2
    assert not result.schema_failure
    assert result.diagnosis.evidence[0].source == "hostapd"


def test_fabricated_citation_is_measured_separately(view):
    fake = ScriptedModel([fabricated()])
    client, _ = client_for(fake)
    with client:
        result = run_arm("llm_tools", view, client=client)
    assert not result.schema_failure
    citations = check(result.diagnosis, view)
    assert citations["valid"] == 0
    assert citations["invalid"] == 1
    assert not citations["all_valid"]


def test_ten_tool_rounds_then_final_without_tools(view):
    script = [tool_call(call_id="call-" + str(number)) for number in range(10)]
    fake = ScriptedModel(script + [answer()])
    client, _ = client_for(fake)
    with client:
        result = run_arm("llm_tools", view, client=client)
    assert not result.schema_failure
    assert len(fake.requests) == 11
    assert all("tools" in request for request in fake.requests[:10])
    assert "tools" not in fake.requests[10]


def test_ignored_tool_cap_gets_only_one_repair(view):
    fake = ScriptedModel([tool_call()], repeat_last=True)
    client, _ = client_for(fake)
    with client:
        result = run_arm("llm_tools", view, client=client)
    assert result.schema_failure
    assert len(fake.requests) == 12
    assert "tools" not in fake.requests[-1]


def test_tool_error_is_returned_as_data(view):
    fake = ScriptedModel([tool_call("get_frame", {"n": 999}), answer()])
    client, _ = client_for(fake)
    with client:
        run_arm("llm_tools", view, client=client)
    assert "error" in fake.requests[1]["messages"][-1]["content"]


def test_trace_is_append_only_complete_and_replayable(view, tmp_path):
    trace = TraceWriter(tmp_path / "trace.jsonl")
    fake = ScriptedModel([tool_call(), answer()])
    client, _ = client_for(fake, supports_seed=True, seed=41)
    with client:
        run_arm("llm_tools", view, client=client, trace=trace,
                run_id="run-1", bundle_id="bundle-1")
    rows = [json.loads(line) for line in trace.path.read_text().splitlines()]
    required = {"run_id", "bundle_id", "arm", "call_index", "messages", "messages_sha256",
                "messages_text", "tool_definitions", "tool_definitions_text",
                "tool_definitions_sha256", "requested_model", "resolved_model", "base_url_host",
                "parameters", "latency_ms", "tokens", "finish_reason", "retry_count",
                "retry_errors", "raw_response_body", "validation_passed", "request",
                "request_text", "request_sha256", "prompt_hashes", "attempts",
                "usage", "cost_inr", "pricing", "cost_details", "view",
                "context_length", "estimated_prompt_tokens", "truncation_suspected"}
    assert len(rows) == 2
    for index, record in enumerate(rows):
        assert required <= record.keys()
        assert record["call_index"] == index
        assert record["resolved_model"] == "fake-resolved-version"
        assert record["base_url_host"] == "localhost"
        assert record["request_sha256"] == fingerprint(record["request"])
        assert json.loads(record["request_text"]) == fake.requests[index]
        assert record["parameters"]["seed"] == 41
        assert record["parameters"]["temperature"] == 0
    response = json.loads(rows[-1]["raw_response_body"])
    diagnosis = json.loads(response["choices"][0]["message"]["content"])
    assert diagnosis["root_cause"] == "unknown"


@pytest.mark.parametrize("first", [httpx.Response(429, text="slow down"),
                                   httpx.Response(503, text="unavailable"),
                                   httpx.ReadTimeout("timeout")])
def test_retry_backoff_and_rate_limit(view, first):
    fake = ScriptedModel([first, answer()])
    client, clock = client_for(fake, rpm=20)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_raw", view, client=client, trace=trace)
    record = trace.records[0]
    assert result.error is None
    assert record["retry_count"] == 1
    assert len(record["retry_errors"]) == 1
    assert len(record["attempts"]) == 2
    assert clock.sleeps == [1, 2]
    assert record["latency_ms"] == 3000


def test_terminal_http_error_is_traced_without_schema_failure(view):
    fake = ScriptedModel([httpx.Response(400, text="bad request")])
    client, _ = client_for(fake)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_raw", view, client=client, trace=trace)
    assert result.error == "HTTP 400"
    assert not result.schema_failure
    assert result.tokens["total"] is None
    assert trace.records[0]["raw_response_body"] == "bad request"
    assert len(fake.requests) == 1


def test_missing_usage_remains_unknown(view):
    response = {"choices": [{"message": answer(), "finish_reason": "stop"}],
                "model": "version-without-usage"}
    fake = ScriptedModel([httpx.Response(200, json=response)])
    client, _ = client_for(fake)
    with client:
        result = run_arm("llm_raw", view, client=client)
    assert result.tokens == {"prompt": None, "completion": None, "total": None}


def test_invalid_response_envelope_is_recorded(view):
    fake = ScriptedModel([httpx.Response(200, json={"choices": []})])
    client, _ = client_for(fake)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_raw", view, client=client, trace=trace)
    assert result.error == "invalid Chat Completions response envelope"
    assert not trace.records[0]["validation_passed"]


def test_trimmed_logs_never_exceed_budget(view):
    view.logs["hostapd"] = ["x" * 300 for _ in range(20)]
    text, trimming = raw_logs(view, 600)
    assert len(text) <= 600
    assert trimming["hostapd"]["trimmed"]
    assert not trimming["hostapd"]["partial_last_line"]
    assert trimming["hostapd"]["included_lines"] == 0
    assert trimming["hostapd"]["omitted_lines"] == 20
    assert not trimming["dhcp_client"]["trimmed"]
    assert "\nwpa_supplicant:" in text


@pytest.mark.parametrize("arm", ["llm_raw", "llm_tools"])
def test_every_request_uses_redacted_view_and_no_label(arm):
    mac = "a0:b1:c2:d3:e4:f5"
    ssid = "PrivateWifi"
    raw = Bundle(Path("hidden-bundle-id"),
                 {"label": "secret-label-value", "parameters": {"ssid": ssid}},
                 {1: {"frame": 1, "ssid": ssid, "addrs": [mac]}},
                 {"hostapd": ["AP-ENABLED " + mac + " ssid='" + ssid + "'"],
                  "wpa_supplicant": [mac.upper() + " " + ssid.encode().hex()],
                  "dhcp_server": [mac + " " + ssid],
                  "dhcp_client": [mac + " " + ssid]},
                 "BSSID " + mac + " ssid=" + ssid)
    redacted = redact_bundle(raw, key=b"test-key-for-every-request-32bytes")
    script = [malformed(), answer()]
    if arm == "llm_tools":
        script = [tool_call("capture_summary"),
                  tool_call("read_log", {"source": "hostapd", "start": 1, "end": 1}),
                  tool_call("get_frame", {"n": 1}), malformed(), answer()]
    fake = ScriptedModel(script)
    client, _ = client_for(fake)
    trace = MemoryTrace()
    with client:
        result = run_arm(arm, redacted, client=client, trace=trace)
    assert not result.schema_failure
    for request in fake.requests:
        rendered = json.dumps(request)
        for original in [mac, mac.upper(), ssid, ssid.encode().hex(),
                         "secret-label-value", "hidden-bundle-id"]:
            assert original not in rendered
    assert "ssid-" in json.dumps(fake.requests)


def test_rejects_credentials_in_url():
    with pytest.raises(ValueError, match="credentials"):
        config(base_url="https://username:password@provider.example/v1")


def test_seed_is_omitted_unless_supported(view):
    fake = ScriptedModel([answer()])
    client, _ = client_for(fake)
    with client:
        run_arm("llm_raw", view, client=client)
    assert "seed" not in fake.requests[0]


def test_raw_bundle_cannot_be_submitted_to_an_arm(view):
    bundle = Bundle(Path("private-path"), {"label": "ok"}, view.frames, view.logs, view.stats)
    with pytest.raises(TypeError, match="redacted View"):
        run_arm("llm_raw", bundle)


def test_retries_are_bounded_and_final_timeout_has_no_response_body(view):
    fake = ScriptedModel([httpx.Response(503, text="first response"),
                          httpx.ReadTimeout("timeout"), httpx.ReadTimeout("timeout")])
    client, clock = client_for(fake, retries=2)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_raw", view, client=client, trace=trace)
    assert result.error == "request timed out"
    assert len(fake.requests) == 3
    assert clock.sleeps == [1, 2]
    assert trace.records[0]["retry_count"] == 2
    assert trace.records[0]["raw_response_body"] is None
    assert trace.records[0]["attempts"][0]["raw_response_body"] == "first response"


def test_credential_echo_is_removed_from_trace(view, monkeypatch):
    dummy = "a-dummy-authorization-value-for-testing"
    monkeypatch.setenv("AIRTRACE_TEST_ONLY_AUTH", dummy)
    fake = ScriptedModel([httpx.Response(400, text="accidental echo: " + dummy)])
    client, _ = client_for(fake, api_key_env="AIRTRACE_TEST_ONLY_AUTH")
    trace = MemoryTrace()
    with client:
        run_arm("llm_raw", view, client=client, trace=trace)
    assert dummy not in json.dumps(trace.records)
    assert "[REDACTED CREDENTIAL]" in trace.records[0]["raw_response_body"]


def test_unset_key_records_failure_without_request(view, monkeypatch):
    monkeypatch.delenv("AIRTRACE_TEST_ONLY_AUTH", raising=False)
    fake = ScriptedModel([answer()])
    client, _ = client_for(fake, api_key_env="AIRTRACE_TEST_ONLY_AUTH")
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_raw", view, client=client, trace=trace)
    assert result.error == "configured API key environment variable is unset"
    assert not fake.requests
    assert not trace.records[0]["validation_passed"]


def test_f3_long_log_retains_head_and_late_failure_with_exact_numbers(view):
    lines = ["startup diagnostic detail " + str(number) for number in range(600)]
    lines[-2] = "authentication failed after final handshake attempt"
    view.logs["wpa_supplicant"] = lines
    text, trimming = raw_logs(view, 4800)
    selected = trimming["wpa_supplicant"]
    assert len(text) <= 4800
    assert "1: startup diagnostic detail 0\n" in text
    assert "599: authentication failed after final handshake attempt\n" in text
    assert selected["omission_marker"] in text
    assert selected["omitted_lines"] > 0
    assert selected["included_lines"] + selected["omitted_lines"] == len(lines)
    assert selected["included_line_numbers"] == (
        selected["head_line_numbers"] + selected["tail_line_numbers"])
    for number in selected["included_line_numbers"]:
        assert str(number) + ": " + lines[number - 1] + "\n" in text
    available = selected["allocated_chars"] - len("wpa_supplicant:\n")
    available -= len("[... 600 lines omitted ...]\n")
    head_chars = sum(len(str(n) + ": " + lines[n - 1] + "\n")
                     for n in selected["head_line_numbers"])
    tail_chars = sum(len(str(n) + ": " + lines[n - 1] + "\n")
                     for n in selected["tail_line_numbers"])
    assert head_chars <= int(available * 0.15)
    assert tail_chars <= available - int(available * 0.15)


def test_f3_raw_default_budget_is_48000_and_is_configurable(view):
    view.logs["hostapd"] = ["diagnostic observation " + str(n) for n in range(700)]
    fake = ScriptedModel([answer(), answer()])
    client, _ = client_for(fake)
    with client:
        default = run_arm("llm_raw", view, client=client)
        small = run_arm("llm_raw", view, client=client, raw_char_budget=1200)
    assert sum(info["allocated_chars"] for info in default.trimming.values()) == 48000
    assert sum(info["allocated_chars"] for info in small.trimming.values()) == 1200
    assert default.trimming["hostapd"]["included_lines"] > small.trimming["hostapd"]["included_lines"]


def test_f8_verified_model_configuration_has_prices_and_no_keys():
    path = Path(__file__).parents[2] / "models.json"
    entries = json.loads(path.read_text(encoding="utf-8"))["models"]
    configs = {entry["name"]: ModelConfig.model_validate(entry) for entry in entries}
    assert set(configs) == {
        "jarvislabs-gpt-oss-120b", "jarvislabs-gemma-4-31b", "jarvislabs-qwen-3.8-27b",
        "gemini-3.5-flash", "ollama-qwen3.5-9b"}
    expected = {
        "jarvislabs-gpt-oss-120b": ("gpt-oss-120b", 9.477, 39.803, 4.739),
        "jarvislabs-gemma-4-31b": ("gemma-4-31b-it", 9.477, 32.222, None),
        "jarvislabs-qwen-3.8-27b": ("qwen-3.8-27b-fp8", 28.431, 222.709, None),
    }
    for name, values in expected.items():
        model = configs[name]
        assert model.base_url == "https://models.jarvislabs.net/v1"
        assert model.api_key_env == "JARVISLABS_API_KEY"
        assert (model.model, model.input_price_inr_per_million,
                model.output_price_inr_per_million,
                model.cached_input_price_inr_per_million) == values
    gemini = configs["gemini-3.5-flash"]
    assert gemini.base_url == "https://generativelanguage.googleapis.com/v1beta/openai"
    assert gemini.model == "gemini-3.5-flash"
    assert gemini.api_key_env == "GEMINI_API_KEY"
    assert gemini.rpm == 8
    assert gemini.input_price_inr_per_million is None
    local = configs["ollama-qwen3.5-9b"]
    assert local.base_url == "http://localhost:11434/v1"
    assert local.model == "qwen3.5:9b"
    assert local.api_key_env == ""
    assert local.input_price_inr_per_million == local.output_price_inr_per_million == 0
    assert all(model.supports_tools for model in configs.values())
    assert all("api_key" not in entry for entry in entries)


def test_f8_full_usage_and_cached_cost_preserved_without_reasoning_double_count(view):
    usage = {"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100,
             "prompt_tokens_details": {"cached_tokens": 400, "provider_detail": "retained"},
             "completion_tokens_details": {"reasoning_tokens": 90},
             "provider_field": {"future_counter": 3}}
    response = envelope(answer())
    response["usage"] = usage
    fake = ScriptedModel([httpx.Response(200, json=response)])
    client, _ = client_for(fake, input_price_inr_per_million=9.477,
                           output_price_inr_per_million=39.803,
                           cached_input_price_inr_per_million=4.739)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_raw", view, client=client, trace=trace)
    expected = (600 * 9.477 + 400 * 4.739 + 100 * 39.803) / 1_000_000
    assert result.cost_inr == pytest.approx(expected)
    assert result.tokens == {"prompt": 1000, "completion": 100, "total": 1100}
    assert trace.records[0]["usage"] == usage
    assert trace.records[0]["cost_inr"] == pytest.approx(expected)
    assert trace.records[0]["cost_details"]["cached_tokens"] == 400
    assert trace.records[0]["cost_details"]["cached_tokens_reported"]
    assert result.pricing["currency"] == "INR"


def test_f8_cost_aggregates_every_tool_round_and_repair(view):
    fake = ScriptedModel([tool_call(), malformed(), answer()])
    client, _ = client_for(fake, input_price_inr_per_million=10,
                           output_price_inr_per_million=20)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_tools", view, client=client, trace=trace)
    assert len(trace.records) == 3
    assert result.cost_inr == pytest.approx(3 * (13 * 10 + 7 * 20) / 1_000_000)
    assert result.cost_inr == pytest.approx(sum(row["cost_inr"] for row in trace.records))
    assert all(not row["cost_details"]["cached_tokens_reported"] for row in trace.records)


def test_f8_null_prices_and_missing_or_invalid_usage_remain_unknown():
    priced = config(input_price_inr_per_million=10, output_price_inr_per_million=20)
    assert estimate_cost(config(), {"prompt_tokens": 1, "completion_tokens": 1})[0] is None
    assert estimate_cost(priced, None)[0] is None
    assert estimate_cost(priced, {"prompt_tokens": 1})[0] is None
    assert estimate_cost(priced, {"prompt_tokens": 1, "completion_tokens": 1,
                                 "prompt_tokens_details": {"cached_tokens": 2}})[0] is None
    assert estimate_cost(priced, {"prompt_tokens": 1, "completion_tokens": 1,
                                 "prompt_tokens_details": {"cached_tokens": 1}})[0] is None
    free = config(input_price_inr_per_million=0, output_price_inr_per_million=0,
                  cached_input_price_inr_per_million=0)
    assert estimate_cost(free, {"prompt_tokens": 100, "completion_tokens": 40})[0] == 0
    with pytest.raises(ValueError):
        config(input_price_inr_per_million=-1)
    with pytest.raises(ValueError):
        config(output_price_inr_per_million=float("inf"))


def test_f8_unknown_tool_call_fields_and_thought_signature_round_trip(view):
    first = tool_call("capture_summary")
    call = first["tool_calls"][0]
    call["extra_content"] = {"google": {"thought_signature": "opaque-signature-value"}}
    call["future_provider_field"] = {"nested": [1, "unchanged", {"flag": True}]}
    call["function"]["future_function_field"] = "preserve-this-too"
    fake = ScriptedModel([first, answer()])
    client, _ = client_for(fake)
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_tools", view, client=client, trace=trace)
    assert not result.schema_failure
    replayed = fake.requests[1]["messages"][2]["tool_calls"][0]
    assert replayed == call
    assert trace.records[1]["messages"][2]["tool_calls"][0] == call


@pytest.mark.parametrize("encoding", ["unicode", "mixed", "nested"])
def test_escaped_credential_echo_is_scrubbed_from_usage_trace_and_next_request(view, monkeypatch, encoding):
    dummy = "dummy-echo-only-value"
    monkeypatch.setenv("AIRTRACE_TEST_ONLY_AUTH", dummy)
    escaped = "".join("\\u" + format(ord(character), "04x") for character in dummy)
    if encoding == "mixed":
        escaped = dummy[:5] + escaped[5 * 6:]
    first = envelope(tool_call())
    first["usage"]["provider_detail"] = {"credential_echo": dummy, "ordinary": "retained"}
    first["choices"][0]["message"]["tool_calls"][0]["future_field"] = dummy
    raw = json.dumps(first).replace(dummy, escaped)
    if encoding == "nested":
        first["usage"]["provider_detail"]["credential_echo"] = json.dumps({"nested": escaped})
        raw = json.dumps(first).replace(dummy, escaped)
    fake = ScriptedModel([httpx.Response(200, text=raw), answer()])
    client, _ = client_for(fake, api_key_env="AIRTRACE_TEST_ONLY_AUTH")
    trace = MemoryTrace()
    with client:
        result = run_arm("llm_tools", view, client=client, trace=trace)
    assert result.outcome == "DIAGNOSED"
    rendered = json.dumps(trace.records) + json.dumps(fake.requests)
    assert dummy not in rendered
    assert escaped not in rendered
    assert "[REDACTED CREDENTIAL]" in rendered
    assert trace.records[0]["usage"]["provider_detail"]["ordinary"] == "retained"
    assert trace.records[0]["usage"]["prompt_tokens"] == 13
    sensitive = trace.records[0]["usage"]["provider_detail"]["credential_echo"]
    if encoding == "nested":
        assert json.loads(sensitive)["nested"] == "[REDACTED CREDENTIAL]"
    else:
        assert sensitive == "[REDACTED CREDENTIAL]"
    assert fake.requests[1]["messages"][2]["tool_calls"][0]["future_field"] == "[REDACTED CREDENTIAL]"
