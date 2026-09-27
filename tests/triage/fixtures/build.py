"""Assemble a small radiotap pcap without capture tools or external packages."""

import json
from pathlib import Path
import struct
import hashlib


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
        "started_at": "2023-11-14T22:13:20+00:00", "ended_at": "2023-11-14T22:13:30+00:00",
        "scenario_started_at": "2023-11-14T22:13:20+00:00", "scenario_started_monotonic_ns": 0,
        "status": "ok", "error": None, "generator_commit": "synthetic",
        "injection_verified": True, "verification": [{"check": "synthetic fixture", "passed": True}],
        "capture_health": {"healthy": True, "ap_beacons": 1},
        "quarantined": False, "quarantine_reasons": [],
        "dhcp_server_started": label != "dhcp_no_server",
    }
    (path / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    refresh_window(path)
    return path


def refresh_window(path):
    """Stamp deliberately synthetic receipts after a test edits its fixture."""
    from lab.window import pcap_records
    meta = json.loads((path / "meta.json").read_text(encoding="utf-8"))
    logs = {}
    for source in ("hostapd", "wpa_supplicant", "dhcp_server", "dhcp_client"):
        content = (path / (source + ".log")).read_bytes()
        count = len(content.decode("utf-8").splitlines())
        logs[source] = {"sha256": hashlib.sha256(content).hexdigest(), "line_count": count,
                        "lines": [{"unix_ns": 1700000000100000000 + number,
                                   "monotonic_ns": 100000000 + number} for number in range(count)]}
    capture = path / "capture.pcap"
    meta["observation_end"] = {"wall_time": "2023-11-14T22:13:29+00:00",
                               "unix_ns": 1700000009000000000, "monotonic_ns": 9000000000}
    meta["observation_window"] = {"version": "receipt-pcap-v1", "logs": logs, "capture": {
        "sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
        "frames": sum(stamp is not None for stamp, _ in pcap_records(capture))}}
    (path / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
