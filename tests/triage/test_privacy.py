import json
from pathlib import Path

import pytest

from triage.arms import run_arm
from triage.data import Bundle
from triage.fake import ScriptedModel, answer, tool_call
from triage.llm import ChatClient, ModelConfig
from triage.redact import Redactor, redact_bundle, ssid_variants


def test_printf_escaped_ssid_matches_literal_pseudonym():
    raw = 'A\x01B"\\\n'
    escaped = r'A\x01B\"\\\n'
    redactor = Redactor(b"x" * 32, [raw])
    assert redactor.text(escaped) == redactor.text(raw)
    assert redactor.text("".join(f"\\x{value:02x}" for value in raw.encode())) == redactor.text(raw)


def test_quoted_log_escape_is_consistent_with_frame():
    raw = 'A\x01B"\\\n'
    escaped = r'A\x01B\"\\\n'
    bundle = Bundle(Path("unused"), {}, {1: {"frame": 1, "ssid": raw}},
                    {"hostapd": ["AP-ENABLED"],
                     "wpa_supplicant": ['SSID="' + escaped + '"'], "dhcp_client": ["started"]},
                    "ssid=" + json.dumps(raw))
    view = redact_bundle(bundle, b"x" * 32)
    pseudonym = view.frames[1]["ssid"]
    assert view.logs["wpa_supplicant"] == ['SSID="' + pseudonym + '"']
    assert view.stats == 'ssid="' + pseudonym + '"'


def test_external_log_only_ssid_is_unescaped_before_hashing():
    bundle = Bundle(Path("unused"), {}, {},
                    {"hostapd": ["AP-ENABLED"], "wpa_supplicant": [r'SSID="A\x01B"'],
                     "dhcp_client": ["started"]}, "")
    view = redact_bundle(bundle, b"x" * 32)
    expected = Redactor(b"x" * 32, ["A\x01B"]).text("A\x01B")
    assert view.logs["wpa_supplicant"] == ['SSID="' + expected + '"']


@pytest.mark.parametrize("identifiers", [["Foo\x01", "FOO\x01"], ["FOO\x01", "Foo\x01"]])
def test_case_sensitive_ssids_keep_distinct_escaped_mappings(identifiers):
    redactor = Redactor(b"x" * 32, identifiers)
    assert redactor.text("Foo\x01") != redactor.text("FOO\x01")
    assert redactor.text(r"Foo\x01") == redactor.text("Foo\x01")
    assert redactor.text(r"FOO\x01") == redactor.text("FOO\x01")
    assert redactor.text(r"Foo\u0001") == redactor.text("Foo\x01")
    assert redactor.text(r"FOO\u0001") == redactor.text("FOO\x01")


@pytest.mark.parametrize("arm", ["llm_raw", "llm_tools"])
def test_off_air_target_and_all_escape_forms_are_absent_from_requests(arm):
    on_air = "VisibleNetwork"
    target = "Absent\x01Network"
    encoded = r"Absent\x01Network"
    mac = "a0:b1:c2:d3:e4:f5"
    bundle = Bundle(Path("private-location"),
                    {"label": "ssid_not_found", "parameters": {"ssid": on_air,
                                                               "station_ssid": target}},
                    {1: {"frame": 1, "ssid": on_air, "addrs": [mac]}},
                    {"hostapd": ["AP-ENABLED " + on_air + " " + mac],
                     "wpa_supplicant": ["Trying SSID=" + encoded + " " + mac.upper()],
                     "dhcp_client": [target.encode().hex() + " " + mac.replace(":", "-")]},
                    'ssid="' + on_air + '" BSSID=' + mac)
    view = redact_bundle(bundle, b"x" * 32)
    script = [answer()]
    if arm == "llm_tools":
        script = [tool_call("capture_summary"),
                  tool_call("read_log", {"source": "wpa_supplicant", "start": 1, "end": 1}),
                  tool_call("read_log", {"source": "dhcp_client", "start": 1, "end": 1}), answer()]
    fake = ScriptedModel(script)
    config = ModelConfig(name="fake", base_url="http://localhost/v1", model="explicit-test",
                         supports_tools=True, rpm=1000000)
    with ChatClient(config, transport=fake.transport, sleep=lambda value: None) as client:
        run_arm(arm, view, client=client)
    for request in fake.requests:
        rendered = json.dumps(request)
        for identifier in (on_air, target, encoded, target.encode().hex(), mac, mac.upper(),
                           mac.replace(":", "-"), "private-location"):
            assert identifier not in rendered
    mapped = Redactor(b"x" * 32, [target]).text(target)
    assert mapped in view.logs["wpa_supplicant"][0]
    assert mapped in view.logs["dhcp_client"][0]


@pytest.mark.parametrize("arm", ["llm_raw", "llm_tools"])
def test_relocated_configuration_path_cannot_disclose_injected_class(arm):
    bundle_name = "wrong_passphrase-1000"
    original = "/home/runner/data/" + bundle_name + "/station.conf"
    path = Path("relocated-artifact") / bundle_name
    bundle = Bundle(path, {"label": "wrong_passphrase"}, {1: {"frame": 1}},
                    {"hostapd": ["AP-ENABLED; config=" + str(path / "hostapd.conf")],
                     "wpa_supplicant": ["Reading configuration file '" + original + "'"],
                     "dhcp_client": ["waiting"]}, "Frames: 1 parsed: 1 errors: 0")
    view = redact_bundle(bundle, b"x" * 32)
    script = [answer()]
    if arm == "llm_tools":
        script = [tool_call("read_log", {"source": "wpa_supplicant", "start": 1, "end": 1}),
                  tool_call("read_log", {"source": "hostapd", "start": 1, "end": 1}), answer()]
    fake = ScriptedModel(script)
    config = ModelConfig(name="fake", base_url="http://localhost/v1", model="explicit-test",
                         supports_tools=True, rpm=1000000)
    with ChatClient(config, transport=fake.transport, sleep=lambda value: None) as client:
        run_arm(arm, view, client=client)
    assert "<bundle>" in view.logs["wpa_supplicant"][0]
    for request in fake.requests:
        rendered = json.dumps(request)
        assert bundle_name not in rendered
        assert "relocated-artifact" not in rendered
        assert original not in rendered


@pytest.mark.parametrize("arm", ["llm_raw", "llm_tools"])
@pytest.mark.parametrize("view_name", ["client", "full"])
def test_f5_known_mac_hex_dump_forms_never_reach_any_model_request(arm, view_name):
    # The three addresses are independently discovered in a frame, metadata,
    # and a colon-form log. Each then occurs in all dump representations.
    addresses = ["02:ab:cd:ef:12:34", "02:bc:de:fa:23:45", "02:cd:ef:ab:34:56"]
    ssids = ["NetworkAlpha", "NetworkBeta"]
    forms = []
    for address in addresses:
        compact = address.replace(":", "")
        forms.extend([address, address.upper(), address.replace(":", "-"),
                      compact, compact.upper(), " ".join(address.split(":")),
                      " ".join(address.upper().split(":"))])
    ssid_forms = sorted(set().union(*(ssid_variants(ssid) for ssid in ssids)))
    lines = ["frame address dump " + form for form in forms]
    lines += ["network dump " + form for form in ssid_forms]
    bundle = Bundle(Path("opaque-bundle"), {"parameters": {
        "station_mac": addresses[1], "ssid": ssids[0], "station_ssid": ssids[1]}},
        {1: {"frame": 1, "addrs": [addresses[0]], "ssid": ssids[0]}},
        {"hostapd": lines, "wpa_supplicant": ["peer=" + addresses[2]] + lines,
         "dhcp_server": lines, "dhcp_client": lines}, "Frames: 1")
    view = redact_bundle(bundle, b"x" * 32, view=view_name)
    script = []
    if arm == "llm_tools":
        script = [tool_call("read_log", {"source": source, "start": 1, "end": 80})
                  for source in view.allowed_sources]
        script += [tool_call("get_frame", {"n": 1})]
    script.append(answer())
    fake = ScriptedModel(script)
    config = ModelConfig(name="fake", base_url="http://localhost/v1", model="explicit-test",
                         supports_tools=True, rpm=1000000)
    with ChatClient(config, transport=fake.transport, sleep=lambda value: None) as client:
        run_arm(arm, view, client=client)
    for request in fake.requests:
        rendered = json.dumps(request)
        for raw in forms + ssid_forms:
            assert raw not in rendered
    redactor = Redactor(b"x" * 32, macs=addresses)
    for address in addresses:
        mapped = redactor.mac(address)
        assert redactor.text(address.replace(":", "")) == mapped.replace(":", "")
        assert redactor.text(address.replace(":", " ").upper()) == mapped.replace(":", " ").upper()


def test_f5_known_mac_inside_contiguous_packet_dump_is_redacted():
    address = "02:ab:cd:ef:12:34"
    raw = address.replace(":", "")
    redactor = Redactor(b"x" * 32, macs=[address])
    mapped = redactor.mac(address).replace(":", "")
    for dump in ["aabb" + raw + "ccdd", "AABB" + raw.upper() + "CCDD"]:
        output = redactor.text(dump)
        assert raw not in output.lower()
        assert mapped in output.lower()
        assert output.lower() == "aabb" + mapped + "ccdd"


@pytest.mark.parametrize("arm", ["llm_raw", "llm_tools"])
def test_f5_client_requests_scrub_mac_known_only_from_excluded_colon_form(arm):
    address = "02:ab:cd:ef:12:34"
    compact = address.replace(":", "")
    bundle = Bundle(Path("opaque-bundle"), {}, {1: {"frame": 1}},
                    {"hostapd": ["hidden server diagnostic peer=" + address],
                     "wpa_supplicant": ["packet dump " + compact], "dhcp_client": []},
                    "Frames: 1")
    view = redact_bundle(bundle, b"x" * 32)
    script = [answer()]
    if arm == "llm_tools":
        script.insert(0, tool_call("read_log", {"source": "wpa_supplicant", "start": 1, "end": 1}))
    fake = ScriptedModel(script)
    config = ModelConfig(name="fake", base_url="http://localhost/v1", model="explicit-test",
                         supports_tools=True, rpm=1000000)
    with ChatClient(config, transport=fake.transport, sleep=lambda value: None) as client:
        run_arm(arm, view, client=client)
    for request in fake.requests:
        rendered = json.dumps(request)
        assert address not in rendered
        assert compact not in rendered
        assert "hidden server diagnostic" not in rendered
