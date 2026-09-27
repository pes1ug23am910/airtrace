"""Freeze daemon output and timestamped capture records before verification.

Untimestamped DHCP lines use their receipt time. Buffered lines received after
the cutoff are conservatively omitted, even if the daemon produced them earlier.
Embedded hostap timestamps are an additional upper bound, never a replacement
for the monotonic receipt cutoff. Packet bytes are copied without decoding Wi-Fi.
"""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import struct
import threading
import time

from lab.scrub import CONTROL_LINE, SCRUB_RULES, retained_control_line_indexes


WINDOW_VERSION = "receipt-pcap-v1"
SOURCES = ("hostapd", "wpa_supplicant", "dhcp_server", "dhcp_client")
DAEMON_TIMESTAMP = re.compile(r"^\s*(\d{9,})(?:\.(\d{1,9}))?(?=[:\s])")
PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),
    b"\xa1\xb2\xc3\xd4": (">", 1000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


def clock_mark() -> dict:
    unix_ns = time.time_ns()
    return {
        "wall_time": datetime.fromtimestamp(unix_ns / 1_000_000_000, timezone.utc).isoformat(),
        "unix_ns": unix_ns,
        "monotonic_ns": time.monotonic_ns(),
    }


def daemon_timestamp_ns(line: str):
    match = DAEMON_TIMESTAMP.match(line)
    if match is None:
        return None
    fraction = (match.group(2) or "").ljust(9, "0")
    return int(match.group(1)) * 1_000_000_000 + int(fraction)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class LogRecorder:
    """Drain one daemon pipe; only a snapshot becomes a model-visible file."""

    def __init__(self, stream, raw_path: Path):
        self.stream = stream
        self.raw_path = Path(raw_path)
        self.records = []
        self.lock = threading.Lock()
        self.error = None
        self.thread = threading.Thread(target=self._read, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _read(self):
        try:
            self.raw_path.parent.mkdir(parents=True, exist_ok=True)
            with self.raw_path.open("wb") as raw:
                while True:
                    incoming = self.stream.readline()
                    if not incoming:
                        break
                    mark = clock_mark()
                    if isinstance(incoming, str):
                        incoming = incoming.encode("utf-8")
                    raw.write(incoming)
                    raw.flush()
                    text = incoming.decode("utf-8", errors="replace")
                    with self.lock:
                        for line in text.splitlines(keepends=True):
                            self.records.append((line, mark))
        except Exception as exc:
            self.error = str(exc)

    def snapshot(self, destination: Path, end: dict, *, scrub=False) -> dict:
        """Freeze received lines; an in-flight pipe read can be omitted conservatively."""
        if self.error is not None:
            raise RuntimeError("daemon log recording failed: " + self.error)
        with self.lock:
            records = list(self.records)
        eligible = []
        for line, mark in records:
            embedded = daemon_timestamp_ns(line)
            if mark["unix_ns"] > end["unix_ns"] or mark["monotonic_ns"] > end["monotonic_ns"]:
                continue
            if embedded is not None and embedded > end["unix_ns"]:
                continue
            eligible.append((line, mark))
        indexes = list(range(len(eligible)))
        if scrub:
            indexes = retained_control_line_indexes([line for line, _ in eligible])
        kept = [eligible[index] for index in indexes]
        destination = Path(destination)
        destination.write_text("".join(line for line, _ in kept), encoding="utf-8", newline="")
        return {
            "sha256": sha256(destination),
            "line_count": len(kept),
            "lines": [{"unix_ns": mark["unix_ns"], "monotonic_ns": mark["monotonic_ns"]}
                      for _, mark in kept],
            "removed_control_lines": len(eligible) - len(kept),
            "omitted_after_cutoff": len(records) - len(eligible),
        }

    def finish(self, timeout=2.0):
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise TimeoutError("daemon log pipe did not close before the deadline")
        self.stream.close()
        if self.error is not None:
            raise RuntimeError("daemon log recording failed: " + self.error)


def pcap_records(path: Path):
    """Yield raw classic-pcap records with exact integer nanosecond timestamps."""
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in PCAP_FORMATS:
            raise ValueError("observation capture requires a complete classic-pcap header")
        endian, multiplier = PCAP_FORMATS[header[:4]]
        major, minor, _, _, snaplen, _ = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or snaplen < 1:
            raise ValueError("unsupported pcap header")
        yield None, header
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("partial pcap record header")
            seconds, fraction, included, original = struct.unpack(endian + "IIII", record)
            if (fraction * multiplier >= 1_000_000_000 or included > snaplen
                    or included > original or included > 1024 * 1024):
                raise ValueError("invalid pcap record lengths or timestamp")
            packet = stream.read(included)
            if len(packet) != included:
                raise ValueError("partial pcap packet")
            yield seconds * 1_000_000_000 + fraction * multiplier, record + packet


def trim_capture(raw: Path, destination: Path, end: dict) -> dict:
    """Copy every complete packet at or before the same scenario cutoff."""
    if Path(raw).resolve() == Path(destination).resolve():
        raise ValueError("raw and visible capture paths must differ")
    kept = 0
    removed = 0
    with Path(destination).open("wb") as output:
        for timestamp, record in pcap_records(raw):
            if timestamp is None or timestamp <= end["unix_ns"]:
                output.write(record)
                kept += timestamp is not None
            else:
                removed += 1
    return {"sha256": sha256(Path(destination)), "frames": kept, "removed_frames": removed}


def validate_window(meta: dict, directory: Path, *, require=True) -> bool:
    """Reject post-window evidence; receipt metadata is provenance, not attestation."""
    end = meta.get("observation_end")
    window = meta.get("observation_window")
    if end is None and window is None and not require:
        return False
    if not isinstance(end, dict) or not isinstance(window, dict):
        raise ValueError("bundle has no observation window")
    if window.get("version") != WINDOW_VERSION:
        raise ValueError("unsupported observation window version")
    for key in ("unix_ns", "monotonic_ns"):
        if type(end.get(key)) is not int or end[key] < 0:
            raise ValueError("invalid observation cutoff")
    wall_ns = wall_timestamp_ns(end.get("wall_time"))
    if abs(wall_ns - end["unix_ns"]) > 1000:
        raise ValueError("observation wall clock disagrees with Unix cutoff")
    if meta.get("scenario_started_at") is not None:
        if wall_timestamp_ns(meta["scenario_started_at"]) > end["unix_ns"]:
            raise ValueError("scenario begins after observation end")
    scenario_monotonic = meta.get("scenario_started_monotonic_ns")
    if scenario_monotonic is not None:
        if type(scenario_monotonic) is not int or not 0 <= scenario_monotonic <= end["monotonic_ns"]:
            raise ValueError("scenario monotonic start is outside the observation window")
    logs = window.get("logs")
    if not isinstance(logs, dict):
        raise ValueError("observation log metadata is missing")
    for source in SOURCES:
        path = Path(directory) / (source + ".log")
        log = logs.get(source)
        if not isinstance(log, dict) or log.get("sha256") != sha256(path):
            raise ValueError("observation log digest mismatch: " + source)
        lines = path.read_bytes().decode("utf-8").splitlines()
        marks = log.get("lines", [])
        if (not isinstance(marks, list) or type(log.get("line_count")) is not int
                or log["line_count"] != len(lines) or len(marks) != len(lines)):
            raise ValueError("observation log receipt count mismatch: " + source)
        previous = -1
        for line, mark in zip(lines, marks):
            if not isinstance(mark, dict):
                raise ValueError("invalid log receipt metadata: " + source)
            for key in ("unix_ns", "monotonic_ns"):
                if type(mark.get(key)) is not int or not 0 <= mark[key] <= end[key]:
                    raise ValueError("post-window log receipt: " + source)
            if mark["monotonic_ns"] < previous:
                raise ValueError("log receipts are not in original order: " + source)
            previous = mark["monotonic_ns"]
            embedded = daemon_timestamp_ns(line)
            if embedded is not None and embedded > end["unix_ns"]:
                raise ValueError("post-window daemon timestamp: " + source)
            if source in SCRUB_RULES["sources"] and CONTROL_LINE.search(line):
                raise ValueError("control echo in visible log: " + source)
    capture = Path(directory) / "capture.pcap"
    record = window.get("capture", {})
    if not isinstance(record, dict) or record.get("sha256") != sha256(capture):
        raise ValueError("observation capture digest mismatch")
    frames = 0
    for timestamp, _ in pcap_records(capture):
        if timestamp is not None:
            if timestamp > end["unix_ns"]:
                raise ValueError("post-window capture frame")
            frames += 1
    if type(record.get("frames")) is not int or record["frames"] != frames:
        raise ValueError("observation capture count mismatch")
    return True


def wall_timestamp_ns(value) -> int:
    """Parse timezone-qualified wall time without floating-point rounding."""
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("invalid observation wall timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("observation wall timestamp needs a timezone")
    elapsed = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000 + elapsed.microseconds * 1000
