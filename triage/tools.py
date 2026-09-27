"""Small, bounded read-only tools over an already redacted view."""

import json
from copy import deepcopy
import multiprocessing
import re

from triage.codes import REASON, STATUS
from triage.data import SOURCES, View, render_frame


OUTPUT_LIMIT = 32000
LINE_LIMIT = 2000
REGEX_LIMIT = 256


def bounded_rows(rows, limit: int) -> dict:
    selected = []
    used = 100
    truncated = False
    for row in rows:
        size = len(json.dumps(row, ensure_ascii=True)) + 2
        if len(selected) >= limit or used + size > OUTPUT_LIMIT:
            truncated = True
            break
        selected.append(row)
        used += size
    return {"items": selected, "truncated": truncated}


def log_row(number: int, line: str) -> dict:
    return {"line": number, "text": line[:LINE_LIMIT],
            "truncated": len(line) > LINE_LIMIT}


def _regex_worker(connection, pattern: str, lines: list[str], limit: int):
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
        rows = (log_row(number, line) for number, line in enumerate(lines, 1)
                if compiled.search(line))
        connection.send(bounded_rows(rows, limit))
    finally:
        connection.close()


def search_safely(pattern: str, lines: list[str], limit: int,
                  timeout: float = 2.0) -> dict:
    if not isinstance(pattern, str) or len(pattern) > REGEX_LIMIT:
        raise ValueError("regex must be a string of at most 256 characters")
    try:
        re.compile(pattern)
    except re.error as error:
        raise ValueError("invalid regex") from error
    # Threads cannot interrupt Python's regex engine. A separate process can
    # always be terminated, including for catastrophic backtracking patterns.
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_regex_worker, args=(child, pattern, lines, limit))
    process.start()
    child.close()
    try:
        if not parent.poll(timeout):
            return {"items": [], "truncated": True, "error": "regex search timed out"}
        try:
            return parent.recv()
        except EOFError:
            return {"items": [], "truncated": True, "error": "regex search failed"}
    finally:
        parent.close()
        process.join(timeout=0.1)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
        if process.is_alive():
            process.kill()
            process.join(timeout=1)
        process.close()


def integer(value, minimum: int, maximum: int, name: str):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")


def definition(name: str, description: str, properties: dict, required=()) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": list(required), "additionalProperties": False}}}


SOURCE_SCHEMA = {"type": "string", "enum": list(SOURCES)}
DEFINITIONS = [
    definition("capture_summary", "Read capture statistics; completeness is observation only.", {}),
    definition("list_frames", "Filter frames in capture order; at most 50 results.", {
        "subtype": {"type": "string"}, "address": {"type": "string"},
        "has_status": {"type": "boolean"}, "has_reason": {"type": "boolean"},
        "eapol_only": {"type": "boolean"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50}}),
    definition("get_frame", "Read canonical redacted JSON for one airtrace frame number.",
               {"n": {"type": "integer", "minimum": 1}}, ("n",)),
    definition("search_log", "Case-insensitive regex, 256 characters maximum, hard time limit.", {
        "source": SOURCE_SCHEMA, "regex": {"type": "string", "maxLength": REGEX_LIMIT},
        "limit": {"type": "integer", "minimum": 1, "maximum": 40}}, ("source", "regex")),
    definition("read_log", "Read at most 80 lines; numbering is 1-based, inclusive.", {
        "source": SOURCE_SCHEMA, "start": {"type": "integer", "minimum": 1},
        "end": {"type": "integer", "minimum": 1}}, ("source", "start", "end")),
    definition("lookup_code", "Look up a selected IEEE 802.11 code; unlisted codes are unknown.", {
        "kind": {"type": "string", "enum": ["status", "reason"]},
        "code": {"type": "integer", "minimum": 0, "maximum": 65535}}, ("kind", "code")),
]


class Toolbox:
    def __init__(self, view):
        if not isinstance(view, View):
            raise TypeError("Toolbox requires a redacted View")
        self.view = view
        self.definitions = deepcopy(DEFINITIONS)
        for entry in self.definitions:
            properties = entry["function"]["parameters"]["properties"]
            if "source" in properties:
                properties["source"]["enum"] = list(view.allowed_sources)

    def capture_summary(self):
        text = self.view.stats
        # Account for JSON escaping, not just unescaped character count.
        while len(json.dumps(text)) > OUTPUT_LIMIT - 100:
            text = text[:len(text) // 2]
        return {"stats": text, "truncated": len(text) != len(self.view.stats)}

    def list_frames(self, subtype=None, address=None, has_status=None,
                    has_reason=None, eapol_only=False, limit=50):
        integer(limit, 1, 50, "limit")
        for value in (has_status, has_reason):
            if value is not None and type(value) is not bool:
                raise ValueError("presence filters must be booleans")
        if type(eapol_only) is not bool:
            raise ValueError("eapol_only must be a boolean")
        matches = []
        for frame in self.view.frames.values():
            if subtype is not None and frame.get("subtype") != subtype:
                continue
            if address is not None and address not in frame.get("addrs", []):
                continue
            if has_status is not None and (frame.get("status_code") is not None) != has_status:
                continue
            if has_reason is not None and (frame.get("reason_code") is not None) != has_reason:
                continue
            if eapol_only and not frame.get("eapol_msg"):
                continue
            matches.append({"frame": frame["frame"], "json": render_frame(frame)})
        return bounded_rows(matches, limit)

    def get_frame(self, n):
        integer(n, 1, 2**63 - 1, "n")
        if n not in self.view.frames:
            raise ValueError("frame number does not exist")
        text = render_frame(self.view.frames[n])
        original = len(text)
        while len(json.dumps(text)) > OUTPUT_LIMIT - 100:
            text = text[:len(text) // 2]
        return {"frame": n, "json": text, "truncated": len(text) != original}

    def lines(self, source):
        if source not in self.view.allowed_sources:
            raise ValueError("log source is outside the selected view")
        return self.view.logs[source]

    def search_log(self, source, regex, limit=40):
        integer(limit, 1, 40, "limit")
        return search_safely(regex, self.lines(source), limit)

    def read_log(self, source, start, end):
        integer(start, 1, 2**63 - 1, "start")
        integer(end, start, start + 79, "end")
        lines = self.lines(source)
        rows = (log_row(number, lines[number - 1])
                for number in range(start, min(end, len(lines)) + 1))
        result = bounded_rows(rows, 80)
        result["total_lines"] = len(lines)
        return result

    def lookup_code(self, kind, code):
        integer(code, 0, 65535, "code")
        if kind not in ("status", "reason"):
            raise ValueError("kind must be status or reason")
        meaning = (STATUS if kind == "status" else REASON).get(code, "unknown")
        return {"kind": kind, "code": code, "meaning": meaning}

    def call(self, name: str, arguments: dict):
        allowed = {entry["function"]["name"] for entry in self.definitions}
        if name not in allowed or not isinstance(arguments, dict):
            return {"error": "invalid tool or arguments"}
        try:
            return getattr(self, name)(**arguments)
        except (TypeError, ValueError):
            return {"error": "invalid arguments or reference; consult the tool schema"}
