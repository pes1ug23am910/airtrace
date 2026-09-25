#include "airtrace.h"

#include <string.h>

static bool available(size_t len, size_t off, size_t need)
{
    return off <= len && need <= len - off;
}

/* Multibyte wire values are decoded bytewise, including on unaligned input. */
static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p)
{
    return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint64_t be64(const uint8_t *p)
{
    uint64_t value = 0;
    size_t i;
    for (i = 0; i < 8; ++i) {
        value = (value << 8) | p[i];
    }
    return value;
}

static bool align_offset(size_t *off, size_t len, size_t alignment)
{
    size_t padding = (alignment - (*off % alignment)) % alignment;
    if (!available(len, *off, padding)) {
        return false;
    }
    *off += padding;
    return true;
}

static uint16_t frequency_channel(uint16_t frequency)
{
    if (frequency == 2484) {
        return 14;
    }
    if (frequency >= 2412 && frequency <= 2472 &&
        (frequency - 2407) % 5 == 0) {
        return (uint16_t)((frequency - 2407) / 5);
    }
    if (frequency >= 4910 && frequency <= 4980 &&
        (frequency - 4000) % 5 == 0) {
        return (uint16_t)((frequency - 4000) / 5);
    }
    if (frequency >= 5000 && frequency <= 5895 &&
        (frequency - 5000) % 5 == 0) {
        return (uint16_t)((frequency - 5000) / 5);
    }
    if (frequency == 5935) {
        return 2;
    }
    if (frequency >= 5955 && frequency <= 7115 &&
        (frequency - 5950) % 5 == 0) {
        return (uint16_t)((frequency - 5950) / 5);
    }
    if (frequency >= 58320 && (frequency - 56160) % 2160 == 0) {
        return (uint16_t)((frequency - 56160) / 2160);
    }
    return 0;
}

static void radiotap_value(size_t index, const uint8_t *p, size_t len,
                          airtrace_frame *out)
{
    uint8_t value[8] = {0};
    size_t copied = len < sizeof(value) ? len : sizeof(value);

    /* A TLV may omit trailing zero bytes; bitmap fields supply their full size. */
    if (copied != 0) {
        memcpy(value, p, copied);
    }
    switch (index) {
    case 0:
        out->has_tsft = true;
        out->tsft = le64(value);
        break;
    case 1:
        out->has_flags = true;
        out->radiotap_flags = value[0];
        out->fcs_present = (value[0] & 0x10u) != 0;
        break;
    case 2:
        out->has_rate = true;
        out->rate = value[0];
        break;
    case 3:
        out->has_channel = true;
        out->freq = le16(value);
        out->channel_flags = le16(value + 2);
        out->channel = frequency_channel(out->freq);
        break;
    case 5:
        out->has_rssi = true;
        /* Conversion through int avoids implementation-defined uint8_t->int8_t. */
        out->rssi_dbm = (int16_t)(value[0] < 128 ? (int)value[0] :
                                (int)value[0] - 256);
        break;
    case 19:
        out->has_mcs = true;
        out->mcs_known = value[0];
        out->mcs_flags = value[1];
        out->mcs_index = value[2];
        break;
    default:
        break;
    }
}

static airtrace_err radiotap_tlvs(const uint8_t *buf, size_t len, size_t off,
                                airtrace_frame *out)
{
    if (!align_offset(&off, len, 4)) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    while (off < len) {
        uint16_t type, size;
        if (!available(len, off, 4)) {
            return AIRTRACE_ERR_TRUNCATED;
        }
        type = le16(buf + off);
        size = le16(buf + off + 2);
        off += 4;
        if (type == 29 || type == 31) {
            return AIRTRACE_ERR_MALFORMED;
        }
        if (!available(len, off, size)) {
            return AIRTRACE_ERR_TRUNCATED;
        }
        radiotap_value(type, buf + off, size, out);
        off += size;
        if (!align_offset(&off, len, 4)) {
            return AIRTRACE_ERR_TRUNCATED;
        }
    }
    return AIRTRACE_OK;
}

static airtrace_err parse_radiotap(const uint8_t *buf, size_t len,
                                 airtrace_frame *out)
{
    /* Sizes of standard fields not extracted here still determine later offsets.
     * Indices 16/17 are legacy retry counters; 18 is the deployed XChannel layout.
     * Source: radiotap.org/fields/defined and Wireshark's radiotap definitions. */
    static const uint8_t alignment[28] = {
        8, 1, 1, 2, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1,
        2, 2, 1, 1, 4, 1, 4, 2, 8, 2, 2, 2, 1, 2
    };
    static const uint8_t sizes[28] = {
        8, 1, 1, 4, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1,
        2, 2, 1, 1, 8, 3, 8, 12, 12, 12, 12, 6, 1, 4
    };
    size_t rt_len, maps_end, map_off, field_off, base = 0;
    uint32_t present;
    bool standard_namespace = true;

    if (len < 8) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    if (buf[0] != 0) {
        return AIRTRACE_ERR_UNSUPPORTED;
    }
    rt_len = le16(buf + 2);
    if (rt_len < 8) {
        return AIRTRACE_ERR_MALFORMED;
    }
    if (rt_len > len) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    out->radiotap_version = buf[0];
    out->radiotap_len = (uint16_t)rt_len;

    /* Locate data first; each chained map is bounded by the declared header. */
    maps_end = 4;
    do {
        if (!available(rt_len, maps_end, 4)) {
            return AIRTRACE_ERR_TRUNCATED;
        }
        present = le32(buf + maps_end);
        maps_end += 4;
    } while ((present & UINT32_C(0x80000000)) != 0);

    field_off = maps_end;
    for (map_off = 4; map_off < maps_end; map_off += 4) {
        unsigned bit;
        bool reset = false;
        present = le32(buf + map_off);
        if ((present & UINT32_C(0x60000000)) == UINT32_C(0x60000000)) {
            return AIRTRACE_ERR_MALFORMED;
        }
        for (bit = 0; bit < 31; ++bit) {
            size_t index;
            if ((present & (UINT32_C(1) << bit)) == 0) {
                continue;
            }
            if (bit == 29) {
                standard_namespace = true;
                reset = true;
                continue;
            }
            if (bit == 30) {
                uint16_t vendor_len;
                if (!align_offset(&field_off, rt_len, 2) ||
                    !available(rt_len, field_off, 6)) {
                    return AIRTRACE_ERR_TRUNCATED;
                }
                vendor_len = le16(buf + field_off + 4);
                field_off += 6;
                if (!available(rt_len, field_off, vendor_len)) {
                    return AIRTRACE_ERR_TRUNCATED;
                }
                field_off += vendor_len;
                standard_namespace = false;
                reset = true;
                continue;
            }
            if (!standard_namespace) {
                /* The vendor skip_length already accounted for these fields. */
                continue;
            }
            index = base + bit;
            if (index == 28) {
                /* TLVs occupy all remaining data; no higher presence bits exist. */
                if ((present & UINT32_C(0xe0000000)) != 0 ||
                    map_off + 4 != maps_end) {
                    return AIRTRACE_ERR_MALFORMED;
                }
                return radiotap_tlvs(buf, rt_len, field_off, out);
            }
            if (index >= sizeof(sizes) / sizeof(sizes[0])) {
                return AIRTRACE_ERR_UNSUPPORTED;
            }
            if (!align_offset(&field_off, rt_len, alignment[index]) ||
                !available(rt_len, field_off, sizes[index])) {
                return AIRTRACE_ERR_TRUNCATED;
            }
            radiotap_value(index, buf + field_off, sizes[index], out);
            field_off += sizes[index];
        }
        base = reset ? 0 : base + 32;
    }
    return AIRTRACE_OK;
}

static airtrace_err parse_ies(const uint8_t *buf, size_t len, size_t off,
                             size_t input_base, airtrace_frame *out)
{
    while (off < len) {
        uint8_t id, size;
        const uint8_t *value;
        airtrace_ie *ie;
        if (!available(len, off, 2)) {
            return AIRTRACE_ERR_TRUNCATED;
        }
        id = buf[off];
        size = buf[off + 1];
        off += 2;
        if (!available(len, off, size)) {
            return AIRTRACE_ERR_TRUNCATED;
        }
        if (out->ie_count == AIRTRACE_MAX_IES) {
            return AIRTRACE_ERR_CAPACITY;
        }
        ie = &out->ies[out->ie_count++];
        ie->id = id;
        ie->len = size;
        ie->offset = input_base + off;
        value = buf + off;
        switch (id) {
        case 0:
            if (size > sizeof(out->ssid)) {
                return AIRTRACE_ERR_MALFORMED;
            }
            if (!out->has_ssid) {
                out->has_ssid = true;
                out->ssid_len = size;
                memcpy(out->ssid, value, size);
            }
            break;
        case 1:
            if (size == 0 || size > sizeof(out->supported_rates)) {
                return AIRTRACE_ERR_MALFORMED;
            }
            if (out->supported_rates_len == 0) {
                out->supported_rates_len = size;
                memcpy(out->supported_rates, value, size);
            }
            break;
        case 3:
            if (size != 1) {
                return AIRTRACE_ERR_MALFORMED;
            }
            if (!out->has_ds_channel) {
                out->has_ds_channel = true;
                out->channel = value[0];
            }
            break;
        case 45:
            if (size != sizeof(out->ht_cap)) {
                return AIRTRACE_ERR_MALFORMED;
            }
            if (!out->has_ht_cap) {
                out->has_ht_cap = true;
                memcpy(out->ht_cap, value, size);
            }
            break;
        case 48:
            if (size < 2) {
                return AIRTRACE_ERR_MALFORMED;
            }
            if (!out->has_rsn) {
                out->has_rsn = true;
                out->rsn_offset = input_base + off;
                out->rsn_len = size;
            }
            break;
        case 191:
            if (size != sizeof(out->vht_cap)) {
                return AIRTRACE_ERR_MALFORMED;
            }
            if (!out->has_vht_cap) {
                out->has_vht_cap = true;
                memcpy(out->vht_cap, value, size);
            }
            break;
        default:
            break;
        }
        off += size;
    }
    return AIRTRACE_OK;
}

static airtrace_err parse_management(const uint8_t *buf, size_t len,
                                    size_t input_base, airtrace_frame *out)
{
    size_t off = out->header_len;
    size_t fixed_len;
    const uint8_t *body;

    switch (out->subtype) {
    case 0: fixed_len = 4; break;  /* Association request. */
    case 1: fixed_len = 6; break;  /* Association response. */
    case 2: fixed_len = 10; break; /* Reassociation request. */
    case 3: fixed_len = 6; break;  /* Reassociation response. */
    case 4: fixed_len = 0; break;  /* Probe request. */
    case 5:                      /* Probe response. */
    case 8: fixed_len = 12; break; /* Beacon. */
    case 10:                     /* Disassociation. */
    case 12: fixed_len = 2; break; /* Deauthentication. */
    case 11: fixed_len = 6; break; /* Authentication. */
    default:
        /* Action bodies and reserved management subtypes are not IE lists. */
        return AIRTRACE_OK;
    }
    if (!available(len, off, fixed_len)) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    body = buf + off;
    switch (out->subtype) {
    case 0:
    case 2:
        out->has_capability = true;
        out->capability = le16(body);
        out->has_listen_interval = true;
        out->listen_interval = le16(body + 2);
        if (out->subtype == 2) {
            out->has_current_ap = true;
            memcpy(out->current_ap, body + 4, 6);
        }
        break;
    case 1:
    case 3:
        out->has_capability = true;
        out->capability = le16(body);
        out->has_status = true;
        out->status_code = le16(body + 2);
        out->has_aid = true;
        out->aid = (uint16_t)(le16(body + 4) & 0x3fffu);
        break;
    case 5:
    case 8:
        out->has_timestamp = true;
        out->timestamp = le64(body);
        out->has_beacon_interval = true;
        out->beacon_interval = le16(body + 8);
        out->has_capability = true;
        out->capability = le16(body + 10);
        break;
    case 10:
    case 12:
        out->has_reason = true;
        out->reason_code = le16(body);
        break;
    case 11:
        out->has_auth = true;
        out->auth_algorithm = le16(body);
        out->auth_seq = le16(body + 2);
        out->has_status = true;
        out->status_code = le16(body + 4);
        break;
    default:
        break;
    }
    if (out->subtype == 11 && out->auth_algorithm >= 3) {
        /* SAE/FILS and later authentication methods have algorithm-specific
         * bodies; interpreting their exchange data as an IE list is unsafe. */
        return AIRTRACE_OK;
    }
    return parse_ies(buf, len, off + fixed_len, input_base, out);
}

static airtrace_err parse_eapol(const uint8_t *buf, size_t len, size_t off,
                               airtrace_frame *out)
{
    static const uint8_t llc_snap[8] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
    const uint8_t *body;
    uint16_t body_len, key_data_len, key_info, message_bits;

    if (!available(len, off, sizeof(llc_snap)) ||
        memcmp(buf + off, llc_snap, sizeof(llc_snap)) != 0) {
        return AIRTRACE_OK;
    }
    off += sizeof(llc_snap);
    if (!available(len, off, 4)) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    body_len = be16(buf + off + 2);
    if (!available(len, off + 4, body_len)) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    if (buf[off + 1] != 3) { /* EAPOL types other than Key. */
        return AIRTRACE_OK;
    }
    off += 4;
    if (body_len == 0) {
        return AIRTRACE_ERR_MALFORMED;
    }
    body = buf + off;
    if (body[0] != 2 && body[0] != 254) {
        return AIRTRACE_OK; /* RC4 and other descriptors have different layouts. */
    }
    if (body_len < 95) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    key_data_len = be16(body + 93);
    if (key_data_len != body_len - 95) {
        return AIRTRACE_ERR_MALFORMED;
    }
    key_info = be16(body + 1);
    out->has_eapol = true;
    out->eapol_key_info = key_info;
    out->eapol_replay_counter = be64(body + 5);
    if ((key_info & 0x0008u) == 0 || (key_info & 0x2c00u) != 0) {
        return AIRTRACE_OK; /* Group keys, requests, errors and SMK are not 4-way. */
    }
    message_bits = (uint16_t)(key_info & 0x03c0u);
    switch (message_bits) {
    case 0x0080:
        out->eapol_msg = 1;
        break;
    case 0x0100:
        /* WPA predates the Secure-bit convention for message 4. */
        out->eapol_msg = (uint8_t)(body[0] == 254 && key_data_len == 0 ? 4 : 2);
        break;
    case 0x01c0:
    case 0x03c0:
        out->eapol_msg = 3;
        break;
    case 0x0300:
        out->eapol_msg = 4;
        break;
    default:
        break;
    }
    return AIRTRACE_OK;
}

static airtrace_err parse_mac(const uint8_t *buf, size_t len, size_t input_base,
                             airtrace_frame *out)
{
    uint16_t fc;
    size_t hdrlen;
    unsigned i;

    if (len < 2) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    fc = le16(buf);
    if ((fc & 3u) != 0) {
        return AIRTRACE_ERR_UNSUPPORTED;
    }
    out->frame_control = fc;
    out->type = (uint8_t)((fc >> 2) & 3u);
    out->subtype = (uint8_t)((fc >> 4) & 15u);
    out->to_ds = (fc & 0x0100u) != 0;
    out->from_ds = (fc & 0x0200u) != 0;
    out->more_fragments = (fc & 0x0400u) != 0;
    out->retry = (fc & 0x0800u) != 0;
    out->protected_frame = (fc & 0x4000u) != 0;

    if (out->type == 3) {
        return AIRTRACE_ERR_UNSUPPORTED;
    }
    if (out->type == 1) {
        if (out->subtype == 12 || out->subtype == 13) {
            hdrlen = 10;
            out->addr_count = 1;
        } else if (out->subtype >= 8) {
            hdrlen = 16;
            out->addr_count = 2;
        } else if (out->subtype == 7) {
            hdrlen = 16; /* Control wrapper: RA, carried FC, HT Control. */
            out->addr_count = 1;
        } else {
            return AIRTRACE_ERR_UNSUPPORTED;
        }
    } else {
        hdrlen = 24;
        out->addr_count = 3;
        if (out->type == 0 && (out->to_ds || out->from_ds)) {
            return AIRTRACE_ERR_MALFORMED;
        }
        if (out->to_ds && out->from_ds) {
            hdrlen += 6;
            out->addr_count = 4;
        }
    }
    if (len < hdrlen) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    out->duration = le16(buf + 2);
    for (i = 0; i < out->addr_count && i < 3; ++i) {
        memcpy(out->addrs[i], buf + 4 + 6 * i, 6);
    }
    if (out->addr_count == 4) {
        memcpy(out->addrs[3], buf + 24, 6);
    }
    if (out->type == 1) {
        if (out->subtype == 10 || out->subtype == 14 || out->subtype == 15) {
            out->has_bssid = true;
            memcpy(out->bssid, out->addrs[out->subtype == 10 ? 0 : 1], 6);
        }
        out->header_len = hdrlen;
        return AIRTRACE_OK;
    }

    out->has_seq = true;
    out->sequence_control = le16(buf + 22);
    out->seq = (uint16_t)(out->sequence_control >> 4);
    out->fragment = (uint8_t)(out->sequence_control & 15u);
    if (!(out->to_ds && out->from_ds)) {
        unsigned bssid_index = out->to_ds ? 0 : out->from_ds ? 1 : 2;
        out->has_bssid = true;
        memcpy(out->bssid, out->addrs[bssid_index], 6);
    }
    if (out->type == 2 && (out->subtype & 8u) != 0) {
        if (!available(len, hdrlen, 2)) {
            return AIRTRACE_ERR_TRUNCATED;
        }
        out->has_qos = true;
        out->qos_control = le16(buf + hdrlen);
        hdrlen += 2;
    }
    if ((fc & 0x8000u) != 0 && (out->has_qos || out->type == 0)) {
        if (!available(len, hdrlen, 4)) {
            return AIRTRACE_ERR_TRUNCATED;
        }
        hdrlen += 4;
    }
    out->header_len = hdrlen;
    if (out->protected_frame || out->more_fragments || out->fragment != 0) {
        return AIRTRACE_OK;
    }
    if (out->type == 0) {
        return parse_management(buf, len, input_base, out);
    }
    if ((out->subtype & 4u) != 0 ||
        (out->has_qos && (out->qos_control & 0x0080u) != 0)) {
        return AIRTRACE_OK; /* Null-data subtypes and A-MSDU are header-only. */
    }
    if ((out->radiotap_flags & 0x20u) != 0 && !align_offset(&hdrlen, len, 4)) {
        return AIRTRACE_ERR_TRUNCATED;
    }
    return parse_eapol(buf, len, hdrlen, out);
}

airtrace_err airtrace_parse_frame(const uint8_t *buf, size_t len, int linktype,
                                airtrace_frame *out)
{
    airtrace_err err;
    size_t off = 0;
    if (out == NULL) {
        return AIRTRACE_ERR_INVALID;
    }
    memset(out, 0, sizeof(*out));
    if (buf == NULL) {
        return AIRTRACE_ERR_INVALID;
    }
    if (linktype == AIRTRACE_LINKTYPE_RADIOTAP) {
        err = parse_radiotap(buf, len, out);
        if (err != AIRTRACE_OK) {
            memset(out, 0, sizeof(*out));
            return err;
        }
        off = out->radiotap_len;
    } else if (linktype != AIRTRACE_LINKTYPE_IEEE802_11) {
        return AIRTRACE_ERR_UNSUPPORTED;
    }
    len -= off;
    if (out->fcs_present) {
        if (len < 4) {
            memset(out, 0, sizeof(*out));
            return AIRTRACE_ERR_TRUNCATED;
        }
        len -= 4;
    }
    err = parse_mac(buf + off, len, off, out);
    if (err != AIRTRACE_OK) {
        memset(out, 0, sizeof(*out));
    }
    return err;
}

const char *airtrace_strerror(airtrace_err err)
{
    switch (err) {
    case AIRTRACE_OK: return "success";
    case AIRTRACE_ERR_INVALID: return "invalid argument";
    case AIRTRACE_ERR_TRUNCATED: return "truncated input";
    case AIRTRACE_ERR_MALFORMED: return "malformed input";
    case AIRTRACE_ERR_UNSUPPORTED: return "unsupported format";
    case AIRTRACE_ERR_CAPACITY: return "fixed capacity exceeded";
    case AIRTRACE_ERR_IO: return "I/O error";
    case AIRTRACE_EOF: return "end of file";
    default: return "unknown error";
    }
}

const char *airtrace_subtype_name(uint8_t type, uint8_t subtype)
{
    static const char *const management[16] = {
        "assoc_req", "assoc_resp", "reassoc_req", "reassoc_resp",
        "probe_req", "probe_resp", "timing_advertisement", "reserved",
        "beacon", "atim", "disassoc", "auth", "deauth", "action",
        "action_no_ack", "reserved"
    };
    static const char *const control[16] = {
        "reserved", "reserved", "trigger", "tack", "beamforming_report_poll",
        "vht_ndp_announcement", "control_extension", "control_wrapper",
        "block_ack_req", "block_ack", "ps_poll", "rts", "cts", "ack",
        "cf_end", "cf_end_ack"
    };
    static const char *const data[16] = {
        "data", "data_cf_ack", "data_cf_poll", "data_cf_ack_poll", "null",
        "cf_ack", "cf_poll", "cf_ack_poll", "qos_data", "qos_data_cf_ack",
        "qos_data_cf_poll", "qos_data_cf_ack_poll", "qos_null", "reserved",
        "qos_cf_poll", "qos_cf_ack_poll"
    };
    if (subtype >= 16) {
        return "unknown";
    }
    switch (type) {
    case 0: return management[subtype];
    case 1: return control[subtype];
    case 2: return data[subtype];
    default: return "unknown";
    }
}
