"""Observation-window regressions use daemon pipes and byte-built pcaps only."""

from io import BytesIO
import struct

import pytest

from lab.scenarios import CLASS_IDS
from lab.window import LogRecorder, SOURCES, WINDOW_VERSION, pcap_records, sha256, trim_capture, validate_window


SECOND = 1_700_000_000
END = {"unix_ns": SECOND * 1_000_000_000 + 500_000_000,
       "monotonic_ns": 50, "wall_time": "2023-11-14T22:13:20.500000+00:00"}


def packet_capture(path, timestamps, endian="<", nanoseconds=False):
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    data = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 127))
    for fraction in timestamps:
        data.extend(struct.pack(endian + "IIII", SECOND, fraction, 1, 1))
        data.extend(b"x")
    path.write_bytes(data)


def mark(monotonic, fraction):
    return {"unix_ns": SECOND * 1_000_000_000 + fraction, "monotonic_ns": monotonic}


def recorder(tmp_path, monkeypatch, content, marks):
    times = iter(marks)
    monkeypatch.setattr("lab.window.clock_mark", lambda: next(times))
    capture = LogRecorder(BytesIO(content.encode()), tmp_path / "raw.log").start()
    capture.finish()
    return capture


def window_bundle(tmp_path, monkeypatch):
    capture = recorder(tmp_path, monkeypatch, "before window closes\n", [mark(10, 100)])
    logs = {source: capture.snapshot(tmp_path / (source + ".log"), END) for source in SOURCES}
    raw = tmp_path / "raw.pcap"
    packet_capture(raw, [100000, 500000, 900000])
    pcap = trim_capture(raw, tmp_path / "capture.pcap", END)
    return {"observation_end": END, "observation_window": {
        "version": WINDOW_VERSION, "logs": logs, "capture": pcap}}


@pytest.mark.parametrize("class_id", CLASS_IDS)
def test_r13_identical_window_omits_late_logs_frames_and_control_queries(tmp_path, monkeypatch, class_id):
    # The helper accepts no class-dependent policy or label.
    content = (f"{SECOND}.100000: daemon event\n"
               "CTRL_IFACE DEAUTHENTICATE aa:bb:cc:dd:ee:ff\n"
               "  continuation bytes\n"
               f"{SECOND}.900000: future clock timestamp\n"
               "verification STA query\n"
               "daemon shutdown\n")
    capture = recorder(tmp_path, monkeypatch, content,
                       [mark(10, 100), mark(20, 200), mark(21, 210), mark(30, 300),
                        mark(60, 600_000_000), mark(70, 700_000_000)])
    visible = tmp_path / "hostapd.log"
    result = capture.snapshot(visible, END, scrub=True)
    assert visible.read_text() == f"{SECOND}.100000: daemon event\n"
    assert result["removed_control_lines"] == 2
    assert result["omitted_after_cutoff"] == 3
    assert result["lines"] == [mark(10, 100)]
    raw = tmp_path / "raw.pcap"
    packet_capture(raw, [100000, 500000, 900000])
    trimmed = trim_capture(raw, tmp_path / "capture.pcap", END)
    assert trimmed["frames"] == 2
    assert trimmed["removed_frames"] == 1
    assert all(stamp <= END["unix_ns"] for stamp, _ in pcap_records(tmp_path / "capture.pcap")
               if stamp is not None)


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nanoseconds", [False, True])
def test_r13_pcap_cutoff_preserves_bytes_endianness_and_timestamp_resolution(tmp_path, endian, nanoseconds):
    raw = tmp_path / "raw.pcap"
    factor = 1000 if nanoseconds else 1
    packet_capture(raw, [100000 * factor, 500000 * factor, 900000 * factor], endian, nanoseconds)
    visible = tmp_path / "capture.pcap"
    result = trim_capture(raw, visible, END)
    assert result["frames"] == 2
    assert visible.read_bytes() == raw.read_bytes()[:24 + 2 * 17]


def test_r13_snapshot_is_immutable_when_raw_log_continues(tmp_path, monkeypatch):
    capture = recorder(tmp_path, monkeypatch, "original daemon line\n", [mark(10, 100)])
    visible = tmp_path / "hostapd.log"
    metadata = capture.snapshot(visible, END)
    capture.records.append(("later verification query\n", mark(60, 600_000_000)))
    with capture.raw_path.open("ab") as stream:
        stream.write(b"later verification query\n")
    assert visible.read_text() == "original daemon line\n"
    assert sha256(visible) == metadata["sha256"]


def test_r13_validation_rejects_post_window_frame_even_with_updated_digest(tmp_path, monkeypatch):
    meta = window_bundle(tmp_path, monkeypatch)
    assert validate_window(meta, tmp_path)
    packet_capture(tmp_path / "capture.pcap", [100000, 900000])
    meta["observation_window"]["capture"]["sha256"] = sha256(tmp_path / "capture.pcap")
    with pytest.raises(ValueError, match="post-window capture"):
        validate_window(meta, tmp_path)


@pytest.mark.parametrize("clock_key", ["unix_ns", "monotonic_ns"])
def test_r13_validation_rejects_post_window_log_receipt(tmp_path, monkeypatch, clock_key):
    meta = window_bundle(tmp_path, monkeypatch)
    meta["observation_window"]["logs"]["dhcp_client"]["lines"][0][clock_key] = END[clock_key] + 1
    with pytest.raises(ValueError, match="post-window log receipt"):
        validate_window(meta, tmp_path)


def test_r13_validation_rejects_future_embedded_timestamp_and_changed_content(tmp_path, monkeypatch):
    meta = window_bundle(tmp_path, monkeypatch)
    path = tmp_path / "wpa_supplicant.log"
    path.write_text(f"{SECOND}.900000: daemon line\n")
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_window(meta, tmp_path)
    meta["observation_window"]["logs"]["wpa_supplicant"]["sha256"] = sha256(path)
    with pytest.raises(ValueError, match="post-window daemon timestamp"):
        validate_window(meta, tmp_path)


def test_r13_empty_logs_and_capture_are_valid_window_artifacts(tmp_path, monkeypatch):
    capture = recorder(tmp_path, monkeypatch, "", [])
    logs = {source: capture.snapshot(tmp_path / (source + ".log"), END) for source in SOURCES}
    packet_capture(tmp_path / "raw.pcap", [])
    pcap = trim_capture(tmp_path / "raw.pcap", tmp_path / "capture.pcap", END)
    assert validate_window({"observation_end": END, "observation_window": {
        "version": WINDOW_VERSION, "logs": logs, "capture": pcap}}, tmp_path)


def test_r13_legacy_window_is_explicit_and_invalid_present_window_never_bypasses(tmp_path):
    with pytest.raises(ValueError, match="no observation window"):
        validate_window({}, tmp_path)
    assert validate_window({}, tmp_path, require=False) is False
    with pytest.raises(ValueError, match="unsupported observation window"):
        validate_window({"observation_end": {}, "observation_window": {}}, tmp_path, require=False)
    with pytest.raises(ValueError, match="no observation window"):
        validate_window({"observation_end": END}, tmp_path, require=False)


@pytest.mark.parametrize("cut", [1, 23, 25, 40])
def test_r13_capture_trimming_rejects_partial_records(tmp_path, cut):
    raw = tmp_path / "raw.pcap"
    packet_capture(raw, [100000])
    raw.write_bytes(raw.read_bytes()[:cut])
    with pytest.raises(ValueError):
        trim_capture(raw, tmp_path / "capture.pcap", END)


def test_r13_capture_input_and_output_must_differ(tmp_path):
    raw = tmp_path / "raw.pcap"
    packet_capture(raw, [100000])
    original = raw.read_bytes()
    with pytest.raises(ValueError, match="must differ"):
        trim_capture(raw, raw, END)
    assert raw.read_bytes() == original


def test_r13_recorder_finish_closes_pipe_idempotently(tmp_path):
    pipe = BytesIO(b"")
    capture = LogRecorder(pipe, tmp_path / "raw.log").start()
    capture.finish()
    capture.finish()
    assert pipe.closed


@pytest.mark.parametrize("wall_time", [None, "invalid", "2023-11-14T22:13:20.500000",
                                       "2023-11-14T22:13:21.500000+00:00"])
def test_r13_validation_rejects_missing_naive_or_disagreeing_wall_clock(tmp_path, monkeypatch, wall_time):
    meta = window_bundle(tmp_path, monkeypatch)
    meta["observation_end"] = {**END, "wall_time": wall_time}
    with pytest.raises(ValueError, match="wall"):
        validate_window(meta, tmp_path)


def test_r13_validation_accepts_equivalent_wall_timezone_and_microsecond_rounding(tmp_path, monkeypatch):
    meta = window_bundle(tmp_path, monkeypatch)
    meta["observation_end"] = {**END, "unix_ns": END["unix_ns"] + 500,
                               "wall_time": "2023-11-15T03:43:20.500000+05:30"}
    assert validate_window(meta, tmp_path)


@pytest.mark.parametrize("field,value", [
    ("scenario_started_at", "2023-11-14T22:13:21+00:00"),
    ("scenario_started_monotonic_ns", 51),
    ("scenario_started_monotonic_ns", -1),
])
def test_r13_validation_rejects_scenario_start_after_cutoff(tmp_path, monkeypatch, field, value):
    meta = window_bundle(tmp_path, monkeypatch)
    meta[field] = value
    with pytest.raises(ValueError, match="scenario"):
        validate_window(meta, tmp_path)


def test_r13_validation_rejects_control_echo_even_if_digest_is_updated(tmp_path, monkeypatch):
    meta = window_bundle(tmp_path, monkeypatch)
    path = tmp_path / "hostapd.log"
    path.write_text("CTRL_IFACE DEAUTHENTICATE 02:11:22:33:44:55\n")
    meta["observation_window"]["logs"]["hostapd"]["sha256"] = sha256(path)
    with pytest.raises(ValueError, match="control echo"):
        validate_window(meta, tmp_path)
