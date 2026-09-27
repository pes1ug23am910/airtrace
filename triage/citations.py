"""Check quotation existence, not whether a quotation proves a diagnosis."""

import json

from triage.data import render_frame
from triage.schema import Diagnosis


CITATION_RULES_VERSION = "2-complete-member-log12-view-auto"


def normalise(text: str) -> str:
    return " ".join(text.split())


def complete_frame_member(frame: dict, quote: str) -> bool:
    """Require a whole top-level member within an exact rendered quote.

    Positions come from actual members, so a number prefix or member-like text
    inside an SSID cannot stand in for a complete JSON value.
    """
    text = render_frame(frame)
    member_spans = []
    position = 1
    for key, value in sorted(frame.items()):
        member = json.dumps({key: value}, sort_keys=True, ensure_ascii=True)[1:-1]
        member_spans.append((position, position + len(member)))
        position += len(member) + 2
    start = text.find(quote)
    while start != -1:
        end = start + len(quote)
        if any(start <= first and last <= end for first, last in member_spans):
            return True
        start = text.find(quote, start + 1)
    return False


def check(diagnosis: Diagnosis, view) -> dict:
    valid = 0
    invalid = 0
    ambiguous_count = 0
    items = []
    for item in diagnosis.evidence:
        if not view.contains_source(item.source):
            matched = False
            occurrences = 0
        elif item.source == "frame":
            frame = view.frames.get(item.ref)
            matched = frame is not None and complete_frame_member(frame, item.quote)
            occurrences = sum(item.quote in render_frame(candidate)
                              for candidate in view.frames.values())
        else:
            lines = view.logs.get(item.source, [])
            text = lines[item.ref - 1] if 1 <= item.ref <= len(lines) else ""
            quote = normalise(item.quote)
            matched = len("".join(quote.split())) >= 12 and quote in normalise(text)
            occurrences = sum(bool(quote) and quote in normalise(line) for line in lines)
        ambiguous = occurrences > 3
        if not item.auto:
            if matched:
                valid += 1
            else:
                invalid += 1
            ambiguous_count += int(ambiguous)
        items.append({"source": item.source, "ref": item.ref,
                      "valid": matched, "ambiguous": ambiguous, "auto": item.auto})
    return {"valid": valid, "invalid": invalid, "all_valid": invalid == 0 and valid > 0,
            "ambiguous": ambiguous_count, "eligible": valid + invalid,
            "auto": sum(item.auto for item in diagnosis.evidence), "items": items}
