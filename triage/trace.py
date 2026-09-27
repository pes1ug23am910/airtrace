"""Append one self-contained JSON record for each completion request."""

import hashlib
import json
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


class TraceWriter:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record):
        # Opening in append mode preserves earlier calls, including failed ones.
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(canonical(record) + "\n")


class MemoryTrace:
    """The same interface for tests and callers that do not persist requests."""

    def __init__(self):
        self.records = []

    def append(self, record):
        self.records.append(json.loads(canonical(record)))
