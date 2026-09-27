"""Assemble a small radiotap pcap without capture tools or external packages."""

import json
from pathlib import Path
import struct


SSID = "private-lab-network"
AP = "02:11:22:33:44:55"
STATION = "02:66:77:88:99:aa"


def mac(value):
    return bytes.fromhex(value.replace(":", ""))


def header(control, destination=STATION, source=AP):
    return struct.pack("<HH", control, 0) + mac(destination) + mac(source) + mac(AP) + b"\0\0"


def capture_bytes():
    beacon = header(0x0080, "ff:ff:ff:ff:ff:ff")
    beacon += struct.pack("<QHH", 0, 100, 0x11)
    beacon += bytes([0, len(SSID)]) + SSID.encode("ascii") + b"\x03\x01\x06"
    auth = header(0x00B0) + struct.pack("<HHH", 0, 2, 0)
    assoc = header(0x0010) + struct.pack("<HHH", 0x11, 0, 1)
    deauth = header(0x00C0) + struct.pack("<H", 3)
    frames = [beacon, auth, assoc, deauth]
    for info in [0x008A, 0x010A, 0x03CA, 0x030A]:
        descriptor = bytearray(95)
        descriptor[0] = 2
        struct.pack_into(">H", descriptor, 1, info)
        payload = b"\xaa\xaa\x03\0\0\0\x88\x8e"
        payload += struct.pack(">BBH", 2, 3, len(descriptor)) + descriptor
        frames.append(header(0x0208) + payload)
    pcap = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
    radiotap = b"\0\0\x08\0\0\0\0\0"
    for number, frame in enumerate(frames, 1):
        packet = radiotap + frame
        pcap.extend(struct.pack("<IIII", 1700000000 + number, 0, len(packet), len(packet)))
        pcap.extend(packet)
    return bytes(pcap)


def build_bundle(path: Path, *, label="ok", seed=1000, split="dev") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "capture.pcap").write_bytes(capture_bytes())
    logs = {
        "hostapd": f"wlan0: AP-ENABLED\n{AP} SSID='{SSID}'\n{STATION} associated\n",
        "wpa_supplicant": f"SSID='{SSID}'\n{STATION} CTRL-EVENT-CONNECTED to {AP}\n",
        "dhcp_server": f"DHCPDISCOVER from {STATION}\nDHCPACK 192.0.2.10 {STATION}\n",
        "dhcp_client": f"DHCPDISCOVER from {STATION}\nbound to 192.0.2.10 -- renewal in 30 seconds.\n",
    }
    if label == "dhcp_no_server":
        logs["dhcp_server"] = ""
    for source, text in logs.items():
        (path / (source + ".log")).write_text(text, encoding="utf-8")
    meta = {
        "label": label, "seed": seed, "split": split,
        "parameters": {"ssid": SSID, "ap_mac": AP, "station_mac": STATION,
                       "passphrase": "fixture-password", "channel": 6},
        "kernel": "synthetic", "tool_versions": {"fixture": "bytes-v1"},
        "started_at": "2026-09-26T00:00:00+00:00", "ended_at": "2026-09-26T00:00:01+00:00",
        "status": "ok", "error": None, "generator_commit": "synthetic",
        "injection_verified": True, "verification": [{"check": "synthetic fixture", "passed": True}],
        "capture_health": {"healthy": True, "ap_beacons": 1},
        "quarantined": False, "quarantine_reasons": [],
        "dhcp_server_started": label != "dhcp_no_server",
    }
    (path / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return path
