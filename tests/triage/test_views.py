"""Named regressions for the client-side observation boundary (R5)."""

from pathlib import Path

import pytest

from triage.citations import check
from triage.data import Bundle, SOURCES, View
from triage.redact import redact_bundle
from triage.schema import Diagnosis, Evidence
from triage.tools import Toolbox


def observations():
    return Bundle(Path("opaque-bundle"), {}, {1: {"frame": 1, "type": "management"}},
                  {"hostapd": ["server-only-secret-value"],
                   "dhcp_server": ["server lease private detail"],
                   "wpa_supplicant": ["client connected observation"],
                   "dhcp_client": ["client requested lease observation"]}, "Frames: 1")


def test_r5_client_view_is_default_and_discards_server_logs():
    bundle = observations()
    view = redact_bundle(bundle, b"k" * 32)
    assert view.name == "client"
    assert view.allowed_sources == ("wpa_supplicant", "dhcp_client")
    assert set(view.logs) == set(view.allowed_sources)
    assert "server-only-secret-value" not in str(view)
    manual = View(bundle.frames, bundle.logs, bundle.stats)
    assert manual.logs == view.logs
    assert set(redact_bundle(bundle, b"k" * 32, view="full").logs) == set(SOURCES)
    with pytest.raises(ValueError, match="client or full"):
        redact_bundle(bundle, view="other")


@pytest.mark.parametrize("source", ["hostapd", "dhcp_server"])
def test_r5_tools_refuse_out_of_view_sources_and_omit_schema_enum(source):
    view = redact_bundle(observations(), b"k" * 32)
    # Even later accidental insertion cannot bypass the tool boundary.
    view.logs[source] = ["server-only-secret-value"]
    tools = Toolbox(view)
    for entry in tools.definitions:
        fields = entry["function"]["parameters"]["properties"]
        if "source" in fields:
            assert fields["source"]["enum"] == list(view.allowed_sources)
    with pytest.raises(ValueError, match="outside"):
        tools.lines(source)
    assert "error" in tools.call("read_log", {"source": source, "start": 1, "end": 1})
    assert "error" in tools.call("search_log", {"source": source, "regex": "."})
    assert tools.get_frame(1)["frame"] == 1
    assert tools.capture_summary()["stats"] == "Frames: 1"
    assert len(tools.list_frames()["items"]) == 1
    assert tools.lookup_code("reason", 3)["code"] == 3


def test_r5_citations_outside_view_are_invalid_even_if_log_was_reinserted():
    view = redact_bundle(observations(), b"k" * 32)
    view.logs["hostapd"] = ["server-only-secret-value"]
    answer = Diagnosis(root_cause="unknown", confidence=0.0, fix="Inspect the client.",
                       evidence=[Evidence(source="hostapd", ref=1,
                                          quote="server-only-secret-value")])
    assert check(answer, view)["invalid"] == 1
    full = redact_bundle(observations(), b"k" * 32, view="full")
    assert check(answer, full)["valid"] == 1


def test_r5_hidden_identifiers_inform_privacy_without_exposing_excluded_source_text():
    bundle = observations()
    bundle.logs["hostapd"] = ["hidden diagnostic: SSID='server-only-secret-value' peer=02:ab:cd:ef:12:34"]
    bundle.logs["wpa_supplicant"] = ["unlabelled server-only-secret-value packet=02abcdef1234"]
    client = redact_bundle(bundle, b"k" * 32)
    full = redact_bundle(bundle, b"k" * 32, view="full")
    assert client.logs["wpa_supplicant"] == full.logs["wpa_supplicant"]
    assert "server-only-secret-value" not in str(client)
    assert "02abcdef1234" not in str(client)
    assert "hostapd" not in client.logs
    assert "hidden diagnostic" not in str(client)


def test_r5_rule_skeleton_receives_only_view_aware_tools(monkeypatch):
    from triage import rules

    seen = []
    def rule(tools):
        seen.append(tools.view.name)
        assert set(tools.view.logs) == {"wpa_supplicant", "dhcp_client"}
        assert "error" in tools.call("read_log", {"source": "hostapd", "start": 1, "end": 1})
        return None
    monkeypatch.setattr(rules, "RULES", (rule,))
    diagnosis = rules.diagnose(redact_bundle(observations(), b"k" * 32))
    assert seen == ["client"]
    assert diagnosis.root_cause == "unknown"
    assert all(item.auto for item in diagnosis.evidence)
