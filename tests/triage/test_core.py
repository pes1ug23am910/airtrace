import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
from pydantic import ValidationError

from triage.citations import check
from triage.data import View, load_bundle, render_frame
from triage.redact import Redactor, redact_bundle
from triage.schema import Diagnosis, Evidence, JSON_SCHEMA, unknown
from triage.tools import OUTPUT_LIMIT, Toolbox, search_safely
from .fixtures.build import AP, SSID, STATION, build_bundle


@pytest.fixture
def binary():
    configured = os.environ.get("AIRTRACE_BIN")
    if configured:
        return configured
    root = Path(__file__).resolve().parents[2]
    for candidate in [root / "build/airtrace", root / ".local/airtrace.exe"]:
        if candidate.exists():
            return str(candidate)
    executable = shutil.which("airtrace")
    if not executable:
        pytest.fail("Build airtrace and set AIRTRACE_BIN; integration tests must not silently skip")
    return executable


@pytest.fixture
def bundle(tmp_path, binary):
    return load_bundle(build_bundle(tmp_path / "synthetic"), binary)


@pytest.fixture
def view(bundle):
    return redact_bundle(bundle, b"fixed-test-key-32-bytes-long!!!!!!", view="full")


def diagnosis(source, ref, quote):
    return Diagnosis(root_cause="unknown", evidence=[Evidence(source=source, ref=ref, quote=quote)],
                     confidence=0.0, fix="Inspect observations.")


def test_byte_fixture_reaches_actual_parser(bundle):
    assert bundle.returncode == 0
    assert len(bundle.frames) == 8
    assert bundle.frames[1]["ssid"] == SSID
    assert bundle.frames[2]["status_code"] == 0
    assert bundle.frames[4]["reason_code"] == 3
    assert [bundle.frames[n]["eapol_msg"] for n in range(5, 9)] == [1, 2, 3, 4]
    assert "complete=yes" in bundle.stats
    assert bundle.logs["hostapd"][0] == "wlan0: AP-ENABLED"


@pytest.mark.parametrize("field,value", [
    ("root_cause", "invented"), ("confidence", 1.1), ("confidence", float("nan")),
    ("evidence", []), ("fix", "x" * 301), ("evidence", [dict(source="frame", ref=0, quote="x")]),
    ("evidence", [dict(source="frame", ref=1, quote="")]),
    ("evidence", [dict(source="frame", ref="1", quote="x")]),
])
def test_schema_rejects_invalid(field, value):
    data = diagnosis("frame", 1, "frame").model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        Diagnosis.model_validate(data)


def test_schema_export_and_extra_fields(view):
    assert JSON_SCHEMA["properties"]["evidence"]["maxItems"] == 6
    data = unknown(view).model_dump()
    data["extra"] = True
    with pytest.raises(ValidationError):
        Diagnosis.model_validate(data)
    assert check(unknown(view), view)["items"][0]["valid"]
    assert check(unknown(view), view)["eligible"] == 0


def test_redaction_consistent_and_label_free(bundle, view):
    text = json.dumps({"frames": view.frames, "logs": view.logs, "stats": view.stats})
    for raw in [SSID, AP, STATION]:
        assert raw not in text
    assert not hasattr(view, "meta")
    assert not hasattr(view, "path")
    mapped_ap = view.frames[1]["bssid"]
    assert mapped_ap in view.logs["hostapd"][1]
    assert int(mapped_ap[:2], 16) & 3 == 2
    assert view.frames[1]["ssid"] in view.logs["wpa_supplicant"][0]
    assert redact_bundle(bundle, b"z" * 32).frames[1]["bssid"] != mapped_ap
    assert bundle.frames[1]["bssid"] == AP


def test_escaped_and_hex_ssid_and_mac_variants():
    ssid = 'private"ssid\\value'
    redactor = Redactor(b"k" * 32, [ssid])
    for text in [ssid, json.dumps(ssid)[1:-1], ssid.encode().hex(),
                 " ".join(f"{byte:02x}" for byte in ssid.encode())]:
        assert redactor.text(text).startswith("ssid-")
    assert redactor.text(AP.upper()) == redactor.text(AP.replace(":", "-"))


@pytest.mark.parametrize("source,ref,quote,valid", [
    ("frame", 1, '"subtype": "beacon"', True),
    ("frame", 999, "beacon", False), ("frame", 1, "fabricated", False),
    ("hostapd", 1, "wlan0: AP-ENABLED", True), ("dhcp_client", 99, "bound", False),
    ("wpa_supplicant", 2, "fabricated", False), ("hostapd", 1, "   ", False),
])
def test_citations(view, source, ref, quote, valid):
    result = check(diagnosis(source, ref, quote), view)
    assert result["valid"] == int(valid)
    assert result["invalid"] == int(not valid)
    assert result["all_valid"] == valid
    assert result["ambiguous"] == 0
    assert result["items"] == [{"source": source, "ref": ref, "valid": valid,
                                "ambiguous": False, "auto": False}]


def test_whitespace_normalisation_and_full_frame(view):
    assert check(diagnosis("dhcp_client", 2, "bound   to\n192.0.2.10"), view)["all_valid"]
    assert check(diagnosis("frame", 1, render_frame(view.frames[1])), view)["all_valid"]


def test_every_tool_and_filters(view):
    tools = Toolbox(view)
    assert "Frames: 8" in tools.capture_summary()["stats"]
    assert len(tools.list_frames(eapol_only=True)["items"]) == 4
    assert len(tools.list_frames(has_status=True)["items"]) == 2
    assert len(tools.list_frames(has_reason=True)["items"]) == 1
    assert len(tools.list_frames(has_reason=False)["items"]) == 7
    assert len(tools.list_frames(subtype="beacon")["items"]) == 1
    assert tools.list_frames(address=view.frames[1]["bssid"])["items"]
    assert tools.get_frame(2)["json"] == render_frame(view.frames[2])
    assert tools.search_log("dhcp_client", "bound")["items"][0]["line"] == 2
    assert tools.read_log("hostapd", 2, 2)["items"][0]["line"] == 2
    assert tools.lookup_code("status", 17)["meaning"] != "unknown"
    assert tools.lookup_code("reason", 3)["meaning"] != "unknown"
    assert tools.lookup_code("status", 65535)["meaning"] == "unknown"


@pytest.mark.parametrize("name,args", [
    ("list_frames", {"limit": 51}), ("list_frames", {"limit": True}),
    ("get_frame", {"n": 99}), ("get_frame", {"n": -1}),
    ("read_log", {"source": "dhcp_client", "start": 1, "end": 81}),
    ("search_log", {"source": "meta", "regex": "."}),
    ("search_log", {"source": "dhcp_client", "regex": "("}),
    ("search_log", {"source": "dhcp_client", "regex": "x" * 257}),
    ("lookup_code", {"kind": "status", "code": -1}), ("__dict__", {}),
])
def test_invalid_tool_calls(view, name, args):
    assert "error" in Toolbox(view).call(name, args)


def test_regex_timeout_is_bounded():
    result = search_safely("(a+)+$", ["a" * 50000 + "!"], 1, timeout=0.2)
    assert result["error"] == "regex search timed out"


def test_output_budgets():
    view = View({n: {"frame": n, "ssid": "x" * 100000} for n in range(1, 100)},
                {"dhcp_client": ["\\" * 30000] * 100}, "\\" * 50000)
    tools = Toolbox(view)
    outputs = [tools.capture_summary(), tools.list_frames(), tools.get_frame(1),
               tools.read_log("dhcp_client", 1, 80)]
    for result in outputs:
        assert len(json.dumps(result)) <= OUTPUT_LIMIT
        assert result["truncated"]


def test_pcap_corruption_is_fatal(tmp_path, binary):
    path = build_bundle(tmp_path / "corrupt")
    with (path / "capture.pcap").open("ab") as stream:
        stream.write(b"short record")
    with pytest.raises(ValueError, match="pcap/I/O"):
        load_bundle(path, binary)


def test_cli_timeout_is_forwarded(tmp_path, monkeypatch):
    path = build_bundle(tmp_path / "timeout")
    def run(command, **kwargs):
        assert kwargs["timeout"] == 0.1
        assert command[-2:] == ["--jsonl", "--stats"]
        raise subprocess.TimeoutExpired(command, 0.1)
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(subprocess.TimeoutExpired):
        load_bundle(path, "configured-binary", timeout=0.1)


@pytest.mark.parametrize("capture,records,errors", [
    ("Network_Join_Nokia_Mobile.pcap", 1180, 0),
    ("wpa-Induction.pcap", 1093, 10),
])
def test_committed_captures_preserve_frame_errors(tmp_path, binary, capture, records, errors):
    path = build_bundle(tmp_path / "public-fixture")
    original = Path(__file__).resolve().parents[1] / "fixtures" / capture
    (path / "capture.pcap").write_bytes(original.read_bytes())
    bundle = load_bundle(path, binary)
    assert len(bundle.frames) == records
    assert sum("error" in frame for frame in bundle.frames.values()) == errors
    assert bundle.returncode == int(errors > 0)
    assert "complete=yes" in bundle.stats
    assert "Pcap record after frame" not in bundle.diagnostics


def test_parser_is_called_once_per_loaded_bundle(tmp_path, binary, monkeypatch):
    calls = []
    original_run = subprocess.run
    def counted(command, **kwargs):
        calls.append(command)
        return original_run(command, **kwargs)
    monkeypatch.setattr(subprocess, "run", counted)
    bundle = load_bundle(build_bundle(tmp_path / "cache"), binary)
    tools = Toolbox(redact_bundle(bundle, b"k" * 32))
    tools.capture_summary()
    tools.list_frames()
    tools.get_frame(1)
    tools.read_log("wpa_supplicant", 1, 3)
    assert len(calls) == 1


def test_frame_quote_requires_exact_json(view):
    assert not check(diagnosis("frame", 1, '"subtype":   "beacon"'), view)["all_valid"]
