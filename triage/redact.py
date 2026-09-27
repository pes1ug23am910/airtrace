"""Keyed, consistent identifier replacement before constructing any request."""

import hashlib
import hmac
import json
import re
import secrets

from triage.data import Bundle, View, VIEW_SOURCES


MAC = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![0-9a-fA-F])")
QUOTED_SSID = re.compile(r'''(?i)\bssid\s*[=:]\s*(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)')''')


def ssid_variants(ssid: str) -> set[str]:
    """Representations used in frame JSON, text logs, and byte dumps."""
    variants = {ssid, json.dumps(ssid, ensure_ascii=True)[1:-1]}
    octets = ssid.encode("latin-1", errors="backslashreplace")
    variants.add(octets.hex())
    variants.add(octets.hex().upper())
    variants.add(" ".join(f"{value:02x}" for value in octets))
    variants.add(" ".join(f"{value:02X}" for value in octets))
    escaped = []
    short = {34: '\\"', 92: "\\\\", 10: "\\n", 13: "\\r", 9: "\\t", 27: "\\e"}
    for value in octets:
        if value in short:
            escaped.append(short[value])
        elif 32 <= value <= 126:
            escaped.append(chr(value))
        else:
            escaped.append(f"\\x{value:02x}")
    variants.add("".join(escaped))
    variants.add("".join(f"\\x{value:02x}" for value in octets))
    # SSIDs are case-sensitive. Only byte-escape digits may change case.
    for variant in list(variants):
        variants.add(re.sub(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})",
                            lambda match: match.group()[:2] + match.group()[2:].upper(),
                            variant))
    return variants


def unescape_ssid(value: str) -> str:
    """Decode quoted log byte escapes without interpreting arbitrary code."""
    short = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "e": "\x1b"}

    def replace(match):
        escape = match.group()[1:]
        if escape.startswith("x"):
            return chr(int(escape[1:], 16))
        if escape.startswith("u"):
            return chr(int(escape[1:], 16))
        return short.get(escape, escape)

    return re.sub(r'''\\(?:x[0-9a-fA-F]{2}|u00[0-9a-fA-F]{2}|["'\\nrtbe])''', replace, value)


class Redactor:
    def __init__(self, key: bytes, ssids=(), sensitive=(), bundle_paths=(), macs=()):
        if len(key) < 16:
            raise ValueError("Use at least 16 random bytes for the redaction key")
        self.key = key
        self.replacements = {}
        for ssid in sorted(ssids):
            if not ssid:
                continue
            replacement = "ssid-" + self.digest("ssid", ssid)[:8]
            for variant in sorted(ssid_variants(ssid)):
                self.replacements[variant] = replacement
        for value in sensitive:
            if value:
                self.replacements[value] = "<redacted-secret>"
        for value in bundle_paths:
            if value:
                self.replacements[value] = "<bundle>"
        known_patterns = [MAC.pattern]
        for address in sorted(set(macs)):
            octets = bytes.fromhex(re.sub(r"[:\s-]", "", address))
            contiguous = octets.hex()
            spaced = r"[ \t]+".join(f"{value:02x}" for value in octets)
            # A complete packet may be one contiguous dump: address bytes need
            # replacement even when adjacent bytes are also hexadecimal.
            known_patterns.append("(?i:" + contiguous + ")")
            known_patterns.append(r"(?<![0-9a-fA-F])(?i:" + spaced + r")(?![0-9a-fA-F])")
        # MAC matches precede SSID substrings. Longest-first literals and a
        # single substitution pass keep generated pseudonyms untouched.
        mac_pattern = "(?P<mac>" + "|".join(known_patterns) + ")"
        keys = sorted(self.replacements, key=lambda value: (-len(value), value))
        alternatives = [mac_pattern] + [re.escape(key) for key in keys]
        self.pattern = re.compile("|".join(alternatives))

    def digest(self, kind: str, value: str) -> str:
        return hmac.new(self.key, (kind + "\0" + value).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def mac(self, value: str) -> str:
        octets = bytes.fromhex(re.sub(r"[:\s-]", "", value))
        canonical = ":".join(f"{part:02x}" for part in octets)
        raw = bytearray.fromhex(self.digest("mac", canonical)[:12])
        raw[0] = (raw[0] | 2) & 254
        return ":".join(f"{part:02x}" for part in raw)

    def text(self, value: str) -> str:
        # One pass prevents an SSID substring or its hex form from rewriting a
        # newly generated pseudonym, or part of a complete MAC address.
        def replace(match):
            original = match.group()
            if match.group("mac") is not None:
                pseudonym = self.mac(original)
                if ":" in original or "-" in original:
                    return pseudonym
                if " " in original or "\t" in original:
                    pseudonym = pseudonym.replace(":", " ")
                else:
                    pseudonym = pseudonym.replace(":", "")
                return pseudonym.upper() if original.isupper() else pseudonym
            return self.replacements[original]
        return self.pattern.sub(replace, value)

    def value(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, dict):
            return {key: self.value(item) for key, item in value.items()}
        return value


def redact_bundle(bundle: Bundle, key: bytes | None = None, view: str = "client") -> View:
    if view not in VIEW_SOURCES:
        raise ValueError("view must be client or full")
    visible_logs = {source: bundle.logs.get(source, []) for source in VIEW_SOURCES[view]}
    ssids = {frame["ssid"] for frame in bundle.frames.values() if frame.get("ssid")}
    sensitive = set()
    macs = set()

    def collect_macs(value):
        if isinstance(value, str):
            macs.update(match.group().lower().replace("-", ":")
                        for match in MAC.finditer(value))
        elif isinstance(value, dict):
            for item in value.values():
                collect_macs(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                collect_macs(item)

    # Identifier knowledge is only a privacy filter. An address known from an
    # excluded log must still be removed from a byte dump in a visible log.
    # Only visible_logs, never the other source text, enter the returned view.
    for value in (bundle.frames, bundle.meta.get("parameters", {}), bundle.logs, bundle.stats):
        collect_macs(value)

    def collect(parameters):
        for name, value in parameters.items():
            if isinstance(value, dict):
                collect(value)
            elif isinstance(value, str):
                if "ssid" in name.lower():
                    ssids.add(value)
                if "passphrase" in name.lower() or name.lower() in ("psk", "password"):
                    sensitive.add(value)

    collect(bundle.meta.get("parameters", {}))
    known_variants = set()
    for ssid in ssids:
        known_variants.update(ssid_variants(ssid))
    for lines in bundle.logs.values():
        for line in lines:
            # Quoted SSID values also cover external bundles without parameters.
            for match in QUOTED_SSID.finditer(line):
                value = match.group(1) if match.group(1) is not None else match.group(2)
                if value not in known_variants:
                    ssids.add(unescape_ssid(value))
    # Debug logs can echo configuration paths containing the injected class.
    # The basename also covers logs captured before an artifact was relocated.
    bundle_paths = {str(bundle.path), bundle.path.as_posix(), bundle.path.name}
    redactor = Redactor(key if key is not None else secrets.token_bytes(32),
                        ssids, sensitive, bundle_paths, macs)
    return View(redactor.value(bundle.frames), redactor.value(visible_logs),
                redactor.text(bundle.stats), name=view)
