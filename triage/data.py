"""Load one immutable experiment bundle; keep CLI results in memory only."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess


SOURCES = ("hostapd", "wpa_supplicant", "dhcp_server", "dhcp_client")
VIEW_SOURCES = {
    "client": ("wpa_supplicant", "dhcp_client"),
    "full": SOURCES,
}


def render_frame(frame: dict) -> str:
    """The exact representation used both in tools and citation checks."""
    return json.dumps(frame, sort_keys=True, ensure_ascii=True)


@dataclass
class Bundle:
    path: Path
    meta: dict
    frames: dict[int, dict]
    logs: dict[str, list[str]]
    stats: str
    returncode: int = 0
    diagnostics: str = ""


@dataclass
class View:
    """Only this label-free, path-free view may enter a model request."""

    frames: dict[int, dict]
    logs: dict[str, list[str]]
    stats: str
    name: str = "client"

    def __post_init__(self):
        if self.name not in VIEW_SOURCES:
            raise ValueError("view must be client or full")
        # A manually constructed view obeys the same boundary as redaction.
        self.logs = {source: list(self.logs.get(source, []))
                     for source in self.allowed_sources}

    @property
    def allowed_sources(self) -> tuple[str, ...]:
        return VIEW_SOURCES[self.name]

    def contains_source(self, source: str) -> bool:
        return source == "frame" or source in self.allowed_sources


def load_bundle(path: str | Path, binary: str | Path | None = None,
                timeout: float = 30, *, require_window: bool = True) -> Bundle:
    from lab.manifest import validate_meta
    from lab.window import validate_window

    path = Path(path)
    meta = json.loads((path / "meta.json").read_text(encoding="utf-8"))
    validate_meta(meta)
    executable = str(binary or os.environ.get("AIRTRACE_BIN", "airtrace"))
    command = [executable, "parse", str(path / "capture.pcap"), "--jsonl", "--stats"]
    completed = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout)
    # Frame errors are ordinary JSONL records. Pcap/I/O/capacity diagnostics
    # are fatal for bundle integrity, even if earlier frames were decoded.
    before, separator, after = completed.stderr.partition("Frames: ")
    unexpected = [line for line in before.splitlines()
                  if not re.fullmatch(r"Frame [0-9]+: .+", line)]
    if (completed.returncode not in (0, 1) or not separator or unexpected
            or "ERROR:" in after or "Pcap record after frame" in before):
        raise ValueError("airtrace pcap/I/O/statistics failure: " + completed.stderr[:2000])
    frames = {}
    for line in completed.stdout.splitlines():
        record = json.loads(line)
        number = record.get("frame")
        if type(number) is not int or number < 1 or number in frames:
            raise ValueError("Invalid or duplicate airtrace frame number")
        frames[number] = record
    if completed.returncode and not any("error" in frame for frame in frames.values()):
        raise ValueError("Unexplained airtrace failure: " + completed.stderr[:2000])
    logs = {}
    for source in SOURCES:
        logs[source] = (path / (source + ".log")).read_text(
            encoding="utf-8", errors="replace").splitlines()
    validate_window(meta, path, require=require_window)
    return Bundle(path, meta, frames, logs, "Frames: " + after,
                  completed.returncode, before)
