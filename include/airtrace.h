#ifndef AIRTRACE_H
#define AIRTRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AIRTRACE_VERSION "0.1.0"
#define AIRTRACE_MAX_IES 128u
#define AIRTRACE_LINKTYPE_IEEE802_11 105
#define AIRTRACE_LINKTYPE_RADIOTAP 127

typedef enum {
    AIRTRACE_OK = 0,
    AIRTRACE_ERR_INVALID,
    AIRTRACE_ERR_TRUNCATED,
    AIRTRACE_ERR_MALFORMED,
    AIRTRACE_ERR_UNSUPPORTED,
    AIRTRACE_ERR_CAPACITY,
    AIRTRACE_ERR_IO,
    AIRTRACE_EOF
} airtrace_err;

typedef struct {
    uint8_t id;
    uint8_t len;
    size_t offset; /* Relative to the caller's input buffer; no borrowed pointers. */
} airtrace_ie;

typedef struct {
    uint8_t radiotap_version;
    uint16_t radiotap_len;
    bool has_tsft, has_flags, has_rate, has_channel, has_rssi, has_mcs;
    uint64_t tsft;
    uint8_t radiotap_flags, rate;
    uint16_t freq, channel_flags;
    int16_t rssi_dbm;
    uint8_t mcs_known, mcs_flags, mcs_index;
    bool fcs_present;

    uint16_t frame_control, duration;
    uint8_t type, subtype;
    bool to_ds, from_ds, retry, protected_frame, more_fragments;
    uint8_t addrs[4][6];
    uint8_t addr_count;
    bool has_bssid;
    uint8_t bssid[6];
    bool has_seq;
    uint16_t seq, sequence_control;
    uint8_t fragment;
    bool has_qos;
    uint16_t qos_control;
    size_t header_len;

    bool has_timestamp, has_beacon_interval, has_capability, has_listen_interval;
    uint64_t timestamp;
    uint16_t beacon_interval, capability, listen_interval;
    bool has_current_ap;
    uint8_t current_ap[6];
    bool has_auth;
    uint16_t auth_algorithm, auth_seq;
    bool has_status, has_aid, has_reason;
    uint16_t status_code, aid, reason_code;

    bool has_ssid;
    uint8_t ssid[32], ssid_len;
    bool has_ds_channel;
    uint16_t channel;
    uint8_t supported_rates[8], supported_rates_len;
    bool has_ht_cap, has_rsn, has_vht_cap;
    uint8_t ht_cap[26], vht_cap[12];
    size_t rsn_offset;
    uint8_t rsn_len;
    airtrace_ie ies[AIRTRACE_MAX_IES];
    size_t ie_count;

    bool has_eapol;
    uint8_t eapol_msg;
    uint16_t eapol_key_info;
    uint64_t eapol_replay_counter;
} airtrace_frame;

/* No allocation. On error, out is cleared. Input and output must not overlap.
 * Unknown radiotap layouts return UNSUPPORTED rather than guessing offsets.
 * Raw 802.11 input has no FCS metadata and is treated as having no FCS. */
airtrace_err airtrace_parse_frame(const uint8_t *buf, size_t len, int linktype,
                                airtrace_frame *out);
const char *airtrace_strerror(airtrace_err err);
const char *airtrace_subtype_name(uint8_t type, uint8_t subtype);

#endif
