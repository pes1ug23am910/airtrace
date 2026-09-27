"""Exercise the actual sealing boundary while daemon and control execution is fake."""

from datetime import datetime, timezone
from io import BytesIO
import json
from types import SimpleNamespace

import pytest

from lab.manifest import validate_meta, verify_manifest, write_manifest
from lab.run_lab import Executor, run_bundle
from lab.scenarios import CLASS_IDS, bundle_id
from lab.window import LogRecorder, pcap_records, sha256, validate_window
from tests.triage.fixtures.build import build_bundle, capture_bytes
from triage.data import load_bundle


SECOND = 1700000000


def mark(seconds):
    return {"wall_time": datetime.fromtimestamp(SECOND + seconds, timezone.utc).isoformat(),
            "unix_ns": int((SECOND + seconds) * 1_000_000_000),
            "monotonic_ns": int(seconds * 1_000_000_000)}


@pytest.mark.parametrize("class_id", CLASS_IDS)
@pytest.mark.parametrize("timeout", [False, True])
def test_r13_runner_seals_all_classes_before_queries_and_cleanup(tmp_path, monkeypatch, class_id, timeout):
    order = []
    instances = []
    clocks = iter([mark(0.5), mark(5)])
    monkeypatch.setattr("lab.run_lab.clock_mark", lambda: next(clocks))
    monkeypatch.setattr("lab.window.clock_mark", lambda: mark(1))
    dates = iter([mark(0)["wall_time"], mark(0)["wall_time"], mark(10)["wall_time"]])
    monkeypatch.setattr("lab.run_lab.utc_now", lambda: next(dates))

    class FakeExecutor(Executor):
        def __init__(self, directory):
            super().__init__(directory)
            instances.append(self)

        def execute(self, step):
            if step["kind"] == "delay" and step["seconds"] == 30 and timeout:
                raise TimeoutError("scenario wait timed out")
            if step["kind"] != "start":
                return
            text = f"{SECOND + 1}.000000: original daemon event\n"
            recorder = LogRecorder(BytesIO(text.encode()), self.directory / "raw" / step["log"]).start()
            recorder.finish()
            self.recorders[step["log"]] = recorder
            self.processes.append((SimpleNamespace(poll=lambda: 0, returncode=0), recorder, step))
            if step["log"] == "tcpdump.log":
                (self.directory / "raw" / "capture.pcap").write_bytes(capture_bytes())

        def healthy(self):
            pass

        def close_observation(self):
            value = super().close_observation()
            order.append("sealed")
            return value

        def late_output(self, event):
            assert self.observation_window is not None
            for source in ("hostapd.log", "wpa_supplicant.log", "dhcp_client.log", "dhcp_server.log"):
                recorder = self.recorders.get(source)
                if recorder is not None:
                    # Deliberately does not contain ctrl_iface: isolation must
                    # hold without relying on the text scrub.
                    text = f"{SECOND + 6}.000000: {event}\n"
                    recorder.records.append((text, mark(6)))
                    with recorder.raw_path.open("ab") as stream:
                        stream.write(text.encode())

        def cleanup(self, commands):
            order.append("cleanup")
            self.late_output("daemon shutdown reason=3")
            return []

    def verify(executor, *args):
        order.append("verify")
        executor.late_output("verification command output")
        return True, [{"check": "synthetic control", "passed": True}]

    def observed(executor, *args):
        order.append("observed")
        executor.late_output("final state query output")
        return {"wpa_state": "COMPLETED", "ipv4_lease_present": True,
                "ap_associated": True, "ap_authorized": True}

    monkeypatch.setattr("lab.run_lab.Executor", FakeExecutor)
    monkeypatch.setattr("lab.run_lab.discover_phys", lambda: ["phy0", "phy1", "phy2"])
    monkeypatch.setattr("lab.run_lab.verify_injection", verify)
    monkeypatch.setattr("lab.run_lab.collect_observed", observed)
    monkeypatch.setattr("lab.run_lab.check_capture_health", lambda *args: {"healthy": True, "ap_beacons": 1})
    directory = tmp_path / bundle_id(class_id, 1000)
    accepted = run_bundle(class_id, "dev", 1000, directory, "synthetic", {})
    assert accepted is not timeout
    assert order == (["sealed", "observed", "cleanup"] if timeout else ["sealed", "verify", "observed", "cleanup"])
    meta = json.loads((directory / "meta.json").read_text())
    assert meta["label"] == class_id
    assert validate_window(meta, directory)
    assert meta["observation_window"]["capture"]["frames"] == 5
    for source in ("hostapd", "wpa_supplicant", "dhcp_client", "dhcp_server"):
        text = (directory / (source + ".log")).read_text()
        assert "query" not in text and "verification" not in text and "shutdown" not in text
        assert all(line["monotonic_ns"] <= meta["observation_end"]["monotonic_ns"]
                   for line in meta["observation_window"]["logs"][source]["lines"])
    assert all(timestamp <= meta["observation_end"]["unix_ns"]
               for timestamp, _ in pcap_records(directory / "capture.pcap") if timestamp is not None)


@pytest.mark.parametrize("kind", ["frame", "log"])
def test_r13_dataset_loader_rejects_post_window_evidence_after_hash_refresh(tmp_path, kind):
    directory = build_bundle(tmp_path / bundle_id("ok", 1000))
    meta = json.loads((directory / "meta.json").read_text())
    if kind == "frame":
        import struct
        path = directory / "capture.pcap"
        with path.open("ab") as stream:
            stream.write(struct.pack("<IIII", SECOND + 10, 0, 1, 1) + b"x")
        meta["observation_window"]["capture"].update(sha256=sha256(path), frames=9)
    else:
        meta["observation_window"]["logs"]["dhcp_client"]["lines"][0]["monotonic_ns"] = 10_000_000_000
    (directory / "meta.json").write_text(json.dumps(meta))
    write_manifest(tmp_path, 1000, "synthetic")
    verify_manifest(tmp_path)
    from tests.lab.test_dataset import test_generated_bundle as validate_generated_bundle
    with pytest.raises(ValueError, match="post-window"):
        validate_generated_bundle(directory)


def test_r13_legacy_bundles_require_explicit_owner_inspection(tmp_path):
    directory = build_bundle(tmp_path / bundle_id("ok", 1000))
    path = directory / "meta.json"
    meta = json.loads(path.read_text())
    del meta["observation_end"]
    del meta["observation_window"]
    path.write_text(json.dumps(meta))
    with pytest.raises(ValueError, match="no observation window"):
        load_bundle(directory)
    assert len(load_bundle(directory, require_window=False).frames) == 8


def test_r14_manifest_discrepancies_are_counts_not_exclusions(tmp_path):
    for label, observed in [
        ("ok", {"wpa_state": "DISCONNECTED", "ipv4_lease_present": False}),
        ("wrong_passphrase", {"wpa_state": "COMPLETED", "ipv4_lease_present": True}),
    ]:
        directory = build_bundle(tmp_path / bundle_id(label, 1000), label=label)
        path = directory / "meta.json"
        meta = json.loads(path.read_text())
        meta["observed"] = observed
        assert not validate_meta(meta).quarantined
        path.write_text(json.dumps(meta))
    manifest = write_manifest(tmp_path, 1000, "synthetic")
    assert verify_manifest(tmp_path) == manifest
    assert manifest["quarantine"]["total"] == 0
    flags = manifest["observed_summary"]["mismatch_counts"]
    assert flags["failure_completed_with_lease"] == flags["ok_missing_completed_or_lease"] == 1
    manifest["observed_summary"]["mismatch_counts"]["failure_completed_with_lease"] = 0
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="observed summary"):
        verify_manifest(tmp_path)


def test_r14_observed_query_exception_does_not_quarantine_or_relabel(tmp_path, monkeypatch):
    from tests.lab.test_review2 import fake_run
    directory = tmp_path / bundle_id("ok", 1000)
    accepted, _ = fake_run(monkeypatch, directory, class_id="ok", observed_failure=True)
    assert accepted
    meta = validate_meta(json.loads((directory / "meta.json").read_text()))
    assert meta.status == "ok" and meta.injection_verified and not meta.quarantined
    assert meta.label == "ok" and meta.observed["wpa_state"] is None
    assert meta.observed["errors"]


def test_r13_spawned_process_is_tracked_even_when_recorder_start_fails(tmp_path, monkeypatch):
    stopped = []
    process = SimpleNamespace(pid=1234, stdout=BytesIO(), returncode=None)
    process.poll = lambda: process.returncode
    def wait(timeout):
        process.returncode = 0
    process.wait = wait
    class FailedRecorder:
        def __init__(self, *args):
            pass
        def start(self):
            raise RuntimeError("synthetic thread creation failure")
        def finish(self):
            process.stdout.close()
    monkeypatch.setattr("lab.run_lab.subprocess.Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr("lab.run_lab.LogRecorder", FailedRecorder)
    monkeypatch.setattr("lab.run_lab.os.killpg", lambda pid, sig: stopped.append(pid), raising=False)
    executor = Executor(tmp_path)
    with pytest.raises(RuntimeError, match="thread creation"):
        executor.execute({"kind": "start", "argv": ["synthetic"], "log": "hostapd.log", "timeout": 10, "required": True})
    assert executor.cleanup([]) == []
    assert stopped == [1234] and process.stdout.closed
