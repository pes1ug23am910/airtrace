"""Remove control-command echoes uniformly; retain daemon event order."""

from pathlib import Path
import re


SCRUB_RULES = {
    "version": "control-echo-v2",
    "sources": ["hostapd", "wpa_supplicant"],
    "remove": "every ctrl_iface/CTRL_IFACE line (RX echoes, 'CTRL_IFACE:' and 'CTRL_IFACE <CMD>' "
              "debug lines) plus indented continuations",
}

# hostapd logs some handled commands without a colon, e.g. "CTRL_IFACE DEAUTHENTICATE <addr>"
# (src/ap/ctrl_iface_ap.c), so match the token itself rather than one spelling of it.
CONTROL_LINE = re.compile(r"ctrl_iface", re.IGNORECASE)


def scrub_control_lines(text: str) -> tuple[str, int]:
    """Retained lines are original daemon lines, with no replacement marker."""
    kept = []
    removed = 0
    continuation = False
    for line in text.splitlines(keepends=True):
        is_echo = bool(CONTROL_LINE.search(line))
        is_continuation = continuation and (not line.strip() or bool(re.match(r"^[ \t]+\S", line)))
        if is_echo or is_continuation:
            removed += 1
            continuation = True
        else:
            kept.append(line)
            continuation = False
    return "".join(kept), removed


def scrub_bundle_logs(directory: Path) -> dict:
    counts = {}
    for source in SCRUB_RULES["sources"]:
        path = directory / (source + ".log")
        text = path.read_text(encoding="utf-8", errors="replace")
        clean, count = scrub_control_lines(text)
        path.write_text(clean, encoding="utf-8", newline="")
        counts[source] = count
    return {"rules": SCRUB_RULES, "removed_lines": counts}
