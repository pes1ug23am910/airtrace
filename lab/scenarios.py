"""Labels describe injected configuration, never an inferred packet signature."""

from dataclasses import asdict, dataclass
import hashlib
import random
import string


CLASS_IDS = (
    "ok", "wrong_passphrase", "akm_mismatch", "pmf_required_unsupported",
    "mac_denied", "ap_full", "dhcp_no_server", "ap_deauth", "ssid_not_found",
)


def bundle_id(class_id: str, seed: int) -> str:
    """An opaque, reproducible name; labels belong only in bundle metadata."""
    return hashlib.sha256(f"airtrace-lab:{class_id}:{seed}".encode("ascii")).hexdigest()[:12]


@dataclass(frozen=True)
class Scenario:
    id: str
    ap_options: str = "wpa_key_mgmt=WPA-PSK\nieee80211w=0\n"
    station_options: str = "key_mgmt=WPA-PSK\n    ieee80211w=1\n"
    actions: tuple[str, ...] = ()
    dhcp_server: bool = True


SCENARIOS = {name: Scenario(name) for name in CLASS_IDS}
SCENARIOS["akm_mismatch"] = Scenario(
    "akm_mismatch", "wpa_key_mgmt=SAE\nieee80211w=2\nsae_require_mfp=1\n",
)
SCENARIOS["pmf_required_unsupported"] = Scenario(
    "pmf_required_unsupported", "wpa_key_mgmt=WPA-PSK\nieee80211w=2\n",
    "key_mgmt=WPA-PSK\n    ieee80211w=0\n",
)
SCENARIOS["mac_denied"] = Scenario("mac_denied", actions=("deny_station",))
SCENARIOS["ap_full"] = Scenario("ap_full", actions=("connect_occupant_first",))
SCENARIOS["dhcp_no_server"] = Scenario("dhcp_no_server", dhcp_server=False)
SCENARIOS["ap_deauth"] = Scenario("ap_deauth", actions=("deauthenticate_after_connection",))


# Only these settings/actions may differ from the control at the same draw.
CAUSAL_KEYS = {
    "ok": {"ap": (), "station": (), "actions": ()},
    "wrong_passphrase": {"ap": (), "station": ("psk",), "actions": ()},
    "akm_mismatch": {"ap": ("wpa_key_mgmt", "ieee80211w", "sae_require_mfp"), "station": (), "actions": ()},
    "pmf_required_unsupported": {"ap": ("ieee80211w",), "station": ("ieee80211w",), "actions": ()},
    "mac_denied": {"ap": ("macaddr_acl", "deny_mac_file"), "station": (), "actions": ("deny_station",)},
    "ap_full": {"ap": ("max_num_sta",), "station": (), "actions": ("connect_occupant_first",)},
    "dhcp_no_server": {"ap": (), "station": (), "actions": ("omit_dhcp_server",)},
    "ap_deauth": {"ap": (), "station": (), "actions": ("deauthenticate_after_connection",)},
    "ssid_not_found": {"ap": (), "station": ("ssid",), "actions": ()},
}

PARAMETER_RANGES = {
    "dev": {"channel": [1, 6], "ap_delay": [0.2, 1.2], "station_delay": [0.2, 1.2]},
    "test": {"channel": [7, 11], "ap_delay": [1.5, 3.0], "station_delay": [1.5, 3.0]},
}


@dataclass(frozen=True)
class Parameters:
    ssid: str
    absent_ssid: str
    passphrase: str
    wrong_passphrase: str
    channel: int
    ap_mac: str
    station_mac: str
    occupant_mac: str
    ap_delay: float
    station_delay: float

    def as_dict(self):
        return asdict(self)


def draw_parameters(seed: int, split: str = "dev") -> Parameters:
    """The local PRNG makes every draw independent of process-global randomness."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if split not in PARAMETER_RANGES:
        raise ValueError("split must be dev or test")
    ranges = PARAMETER_RANGES[split]
    rng = random.Random(seed)

    def token(length):
        return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(length))

    def mac():
        octets = [rng.randrange(256) for _ in range(6)]
        octets[0] = (octets[0] | 2) & 254
        return ":".join(f"{value:02x}" for value in octets)

    ssid = "airtrace-" + token(12)
    absent_ssid = "airtrace-" + token(12)
    while absent_ssid == ssid:
        absent_ssid = "airtrace-" + token(12)
    password = token(20)
    wrong_password = token(20)
    if wrong_password == password:
        wrong_password = "A" + password[1:] if password[0] != "A" else "B" + password[1:]
    addresses = []
    while len(addresses) < 3:
        address = mac()
        if address not in addresses:
            addresses.append(address)
    return Parameters(
        ssid, absent_ssid, password, wrong_password, rng.randint(*ranges["channel"]),
        addresses[0], addresses[1], addresses[2],
        round(rng.uniform(*ranges["ap_delay"]), 3), round(rng.uniform(*ranges["station_delay"]), 3),
    )


def render_configs(class_id: str, parameters: Parameters, directory: str) -> dict[str, str]:
    """Render safe ASCII configuration; generated tokens need no config escaping."""
    scenario = SCENARIOS[class_id]
    p = parameters
    ap = (
        "interface=wlan0\ndriver=nl80211\n"
        f"ctrl_interface={directory}/ap-control\nssid={p.ssid}\n"
        f"hw_mode=g\nchannel={p.channel}\nbssid={p.ap_mac}\n"
        "auth_algs=1\nwpa=2\nrsn_pairwise=CCMP\n"
        f"wpa_passphrase={p.passphrase}\n" + scenario.ap_options
    )
    if class_id == "mac_denied":
        ap += f"macaddr_acl=0\ndeny_mac_file={directory}/deny.txt\n"
    if class_id == "ap_full":
        ap += "max_num_sta=1\n"
    ssid = p.absent_ssid if class_id == "ssid_not_found" else p.ssid
    password = p.wrong_passphrase if class_id == "wrong_passphrase" else p.passphrase

    def station(network, secret, control):
        return (
            f"ctrl_interface={directory}/{control}\nupdate_config=0\n"
            "network={\n"
            f'    ssid="{network}"\n    psk="{secret}"\n'
            "    scan_ssid=1\n    " + scenario.station_options + "}\n"
        )

    dnsmasq = (
        "interface=wlan0\nbind-interfaces\nport=0\n"
        "dhcp-range=192.0.2.20,192.0.2.100,255.255.255.0,10m\n"
        "dhcp-option=3,192.0.2.1\nlog-dhcp\nlog-facility=-\n"
        f"dhcp-leasefile={directory}/dnsmasq.leases\npid-file={directory}/dnsmasq.pid\n"
        "user=root\n"
    )
    script = (
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  bound|renew)\n"
        '    ip -4 address flush dev "$interface" scope global\n'
        '    ip address add "$ip/24" dev "$interface"\n'
        "    ;;\nesac\nexit 0\n"
    )
    return {
        "hostapd.conf": ap,
        "station.conf": station(ssid, password, "sta-control"),
        "occupant.conf": station(p.ssid, p.passphrase, "occupant-control"),
        "deny.txt": p.station_mac + "\n",
        "dnsmasq.conf": dnsmasq,
        "dhcp-script.sh": script,
    }


def seed_schedule(seed_base: int, per_class: int = 12, split: str = "all") -> list[tuple[str, int]]:
    """A complete class has four dev draws, then eight test draws with held-out seeds and parameter range."""
    if not 1 <= per_class <= 12:
        raise ValueError("per-class must be 1..12 (12 is the complete evaluation dataset)")
    if split not in ("dev", "test", "all"):
        raise ValueError("split must be dev, test or all")
    schedule = [("dev", seed_base + offset) for offset in range(4)]
    schedule += [("test", seed_base + 100 + offset) for offset in range(8)]
    return [entry for entry in schedule[:per_class] if split == "all" or entry[0] == split]
