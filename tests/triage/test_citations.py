"""Named quote-strength and automatic-citation regressions (F4, R8)."""

from triage.citations import CITATION_RULES_VERSION, check
from triage.data import View
from triage.schema import Diagnosis, Evidence, unknown


def diagnosis(source, quote, ref=1, auto=False):
    return Diagnosis(root_cause="unknown", evidence=[Evidence(
        source=source, ref=ref, quote=quote, auto=auto)], confidence=0.0, fix="Inspect.")


def test_f4_frame_quote_requires_complete_actual_json_member():
    view = View({1: {"frame": 1, "type": "management", "reason_code": 30,
                     "ssid": '"reason_code": 3'}}, {}, "")
    for quote in ['"type"', '"reason_code": 3', '"type": "manage',
                  '\\"reason_code\\": 3', '"absent": 30']:
        assert check(diagnosis("frame", quote), view)["invalid"] == 1
    for quote in ['"reason_code": 30', '"type": "management"']:
        assert check(diagnosis("frame", quote), view)["valid"] == 1


def test_f4_log_quote_needs_twelve_non_whitespace_characters():
    view = View({}, {"dhcp_client": ["abcdefghijklmnop", "ab cd ef gh ij kl"]}, "")
    assert check(diagnosis("dhcp_client", "abcdefghijk"), view)["invalid"] == 1
    assert check(diagnosis("dhcp_client", "abcdefghijkl"), view)["valid"] == 1
    assert check(diagnosis("dhcp_client", "ab  cd\nef gh ij kl", ref=2), view)["valid"] == 1


def test_f4_ambiguity_counts_matching_locations_not_repetitions():
    frames = {number: {"frame": number, "type": "management"} for number in range(1, 5)}
    view = View(frames, {"dhcp_client": ["distinctive phrase distinctive phrase"] * 4}, "")
    for source, quote in [("frame", '"type": "management"'),
                          ("dhcp_client", "distinctive phrase")]:
        result = check(diagnosis(source, quote), view)
        assert result["valid"] == result["ambiguous"] == 1
        assert result["items"][0]["ambiguous"]
    view.logs["dhcp_client"] = ["distinctive phrase " * 5] * 3
    assert check(diagnosis("dhcp_client", "distinctive phrase"), view)["ambiguous"] == 0


def test_r8_unknown_auto_citations_are_flagged_and_excluded():
    view = View({1: {"frame": 1}}, {"dhcp_client": ["long-enough-observation"] * 4}, "")
    answer = unknown(view)
    assert answer.evidence[0].auto is True
    result = check(answer, view)
    assert result["auto"] == 1
    assert result["eligible"] == result["valid"] == result["invalid"] == result["ambiguous"] == 0
    assert result["all_valid"] is False
    assert result["items"][0] == {"source": "dhcp_client", "ref": 1,
                                   "valid": True, "ambiguous": True, "auto": True}
    assert CITATION_RULES_VERSION


def test_r8_non_model_rule_citations_also_receive_auto_provenance(monkeypatch):
    from triage import rules

    view = View({1: {"frame": 1}}, {}, "")
    monkeypatch.setattr(rules, "RULES", (lambda tools: diagnosis("frame", '"frame": 1'),))
    answer = rules.diagnose(view)
    assert answer.evidence[0].auto is True
    assert check(answer, view)["eligible"] == 0
