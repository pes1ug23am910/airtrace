"""R14 record-only outcome regressions using control-query fakes."""

import json
from types import SimpleNamespace

import pytest

from lab.outcomes import collect_observed, observation_commands, observed_summary
from lab.scenarios import CLASS_IDS, draw_parameters


class QueryExecutor:
    def __init__(self, commands, replies):
        self.commands = commands
        self.replies = replies
        self.calls = []

    def run(self, argv, timeout, check):
        self.calls.append({"argv": argv, "timeout": timeout, "check": check})
        name = next(name for name, command in self.commands.items() if argv == command)
        reply = self.replies[name]
        if isinstance(reply, Exception):
            raise reply
        return SimpleNamespace(returncode=0, stdout=reply, stderr="")


def replies(parameters, state="COMPLETED", ipv4=True, flags="[AUTH][ASSOC][AUTHORIZED]"):
    return {
        "station_status": "wpa_state=" + state + "\n",
        "station_ipv4": json.dumps([{"ifname": "wlan1", "addr_info":
            [{"family": "inet", "local": "192.0.2.20"}] if ipv4 else []}]),
        "ap_stations": parameters.station_mac + "\nflags=" + flags + "\n",
    }


@pytest.mark.parametrize("class_id", CLASS_IDS)
def test_r14_every_class_queries_the_same_record_only_outcomes(tmp_path, class_id):
    parameters = draw_parameters(1000)
    commands = observation_commands(class_id, 1000, tmp_path)
    executor = QueryExecutor(commands, replies(parameters))
    result = collect_observed(executor, class_id, 1000, tmp_path, parameters)
    assert result["wpa_state"] == "COMPLETED"
    assert result["ipv4_lease_present"] is True
    assert result["ap_associated"] is True and result["ap_authorized"] is True
    assert result["errors"] == []
    assert set(commands) == {"station_status", "station_ipv4", "ap_stations"}
    assert [call["argv"] for call in executor.calls] == list(commands.values())
    assert all(call["timeout"] == 10 and call["check"] is False for call in executor.calls)
    assert all(isinstance(command, list) for command in commands.values())
    assert [item["name"] for item in result["queries"]] == list(commands)
    assert all(item["returncode"] == 0 and "stdout" in item for item in result["queries"])
    assert "quarantined" not in result and "label" not in result


@pytest.mark.parametrize("flags,associated,authorized", [
    ("[AUTH]", False, False), ("[AUTH][ASSOC]", True, False),
    ("[AUTH][ASSOC][AUTHORIZED]", True, True),
])
def test_r14_ap_flags_describe_target_association_and_authorization(tmp_path, flags, associated, authorized):
    parameters = draw_parameters(1000)
    outputs = replies(parameters, flags=flags)
    outputs["ap_stations"] = "02:00:00:00:00:ff\nflags=[ASSOC][AUTHORIZED]\n" + outputs["ap_stations"]
    executor = QueryExecutor(observation_commands("ok", 1000, tmp_path), outputs)
    result = collect_observed(executor, "ok", 1000, tmp_path, parameters)
    assert result["ap_associated"] is associated
    assert result["ap_authorized"] is authorized


def test_r14_absent_station_and_ipv4_are_false_only_from_successful_queries(tmp_path):
    parameters = draw_parameters(1000)
    outputs = replies(parameters, state="SCANNING", ipv4=False)
    outputs["ap_stations"] = ""
    result = collect_observed(QueryExecutor(observation_commands("ok", 1000, tmp_path), outputs),
                              "ok", 1000, tmp_path, parameters)
    assert result["wpa_state"] == "SCANNING"
    assert result["ipv4_lease_present"] is False
    assert result["ap_associated"] is False and result["ap_authorized"] is False
    assert result["errors"] == []


def test_r14_failed_queries_remain_unknown_and_do_not_change_other_results(tmp_path):
    parameters = draw_parameters(1000)
    outputs = replies(parameters)
    outputs.update(station_status=TimeoutError("query timeout"), station_ipv4="not JSON", ap_stations="FAIL\n")
    result = collect_observed(QueryExecutor(observation_commands("ok", 1000, tmp_path), outputs),
                              "ok", 1000, tmp_path, parameters)
    assert all(result[name] is None for name in ("wpa_state", "ipv4_lease_present", "ap_associated", "ap_authorized"))
    assert {error["query"] for error in result["errors"]} == {"station_status", "station_ipv4", "ap_stations"}
    assert len(result["queries"]) == 3


def test_r14_missing_target_flags_are_unknown_not_false(tmp_path):
    parameters = draw_parameters(1000)
    outputs = replies(parameters)
    outputs["ap_stations"] = parameters.station_mac + "\naid=1\n"
    result = collect_observed(QueryExecutor(observation_commands("ok", 1000, tmp_path), outputs),
                              "ok", 1000, tmp_path, parameters)
    assert result["ap_associated"] is None and result["ap_authorized"] is None
    assert result["wpa_state"] == "COMPLETED" and result["ipv4_lease_present"] is True


def test_r14_summary_counts_discrepancies_and_unknowns_without_excluding_or_relabelling():
    successful = {"wpa_state": "COMPLETED", "ipv4_lease_present": True, "ap_associated": True, "ap_authorized": True}
    unsuccessful = {"wpa_state": "SCANNING", "ipv4_lease_present": False, "ap_associated": False, "ap_authorized": False}
    records = [
        {"label": "ok", "observed": successful}, {"label": "ok", "observed": unsuccessful},
        {"label": "ok", "observed": None}, {"label": "wrong_passphrase", "observed": successful},
        {"label": "wrong_passphrase", "observed": unsuccessful},
    ]
    before = json.dumps(records, sort_keys=True)
    result = observed_summary(records)
    assert json.dumps(records, sort_keys=True) == before
    assert result["by_class"]["ok"]["bundles"] == 3
    assert result["by_class"]["ok"]["recorded"] == 2
    assert result["by_class"]["ok"]["wpa_state"] == {"COMPLETED": 1, "SCANNING": 1, "unknown": 1}
    assert result["by_class"]["wrong_passphrase"]["bundles"] == 2
    assert result["mismatch_counts"] == {"failure_completed_with_lease": 1, "ok_missing_completed_or_lease": 1, "outcome_unknown": 1}
    assert sum(item["count"] for item in result["by_class"]["ok"]["joint"]) == 3
    assert "quarantined" not in json.dumps(result)
