"""Selected IEEE 802.11 status/reason codes, not a diagnostic rule set.

Source: hostapd 2.10 src/common/ieee802_11_defs.h, WLAN_STATUS_* and
WLAN_REASON_* definitions, mirroring IEEE Std 802.11 status/reason tables.
https://w1.fi/cgit/hostap/plain/src/common/ieee802_11_defs.h?h=hostap_2_10
This intentionally small transcription leaves unlisted codes unknown.
"""

STATUS = {
    0: "Successful",
    1: "Unspecified failure",
    10: "Cannot support all requested capabilities",
    13: "Authentication algorithm not supported",
    14: "Unknown authentication transaction number",
    15: "Challenge failure",
    16: "Authentication timeout",
    17: "AP unable to handle additional associated stations",
    18: "Association denied: unsupported basic rates",
    30: "Association rejected temporarily",
    31: "Robust management frame policy violation",
    40: "Invalid information element",
    41: "Invalid group cipher",
    42: "Invalid pairwise cipher",
    43: "Invalid AKMP",
    44: "Unsupported RSN information element version",
    45: "Invalid RSN information element capabilities",
    46: "Cipher suite rejected by security policy",
    76: "Anti-clogging token required",
    77: "Finite cyclic group not supported",
}

REASON = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Sending station is leaving the IBSS or ESS",
    4: "Disassociated due to inactivity",
    5: "AP unable to handle all currently associated stations",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Sending station is leaving the BSS",
    9: "Station requesting association is not authenticated",
    14: "MIC failure",
    15: "Four-way handshake timeout",
    16: "Group key handshake timeout",
    17: "Information element differs from association exchange",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected by security policy",
}
