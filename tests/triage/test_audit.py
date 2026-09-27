import csv
from io import StringIO

from triage.audit import write_audit_sample


def test_r8_audit_sample_is_stratified_deterministic_and_unjudged(tmp_path):
    rows = []
    for label in ("ok", "ap_deauth"):
        for arm in ("rules", "llm_raw", "llm_tools"):
            for number in range(7):
                rows.append({"bundle_id": str(number), "label": label, "arm": arm,
                             "view": "client", "model_name": "scripted",
                             "diagnosis": {"root_cause": label, "evidence": [
                                 {"source": "dhcp_client", "ref": 1, "quote": "line from daemon", "auto": arm == "rules"}]}})
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    write_audit_sample(rows, first)
    write_audit_sample(list(reversed(rows)), second)
    assert first.read_bytes() == second.read_bytes()
    samples = list(csv.DictReader(StringIO(first.read_text(encoding="utf-8"))))
    assert len(samples) == 18
    for label in ("ok", "ap_deauth"):
        for arm in ("rules", "llm_raw", "llm_tools"):
            assert sum(item["class"] == label and item["arm"] == arm for item in samples) == 3
    assert all(item["supports_diagnosis"] == "" for item in samples)
    assert all("auto" in item["cited_quotes"] for item in samples)
