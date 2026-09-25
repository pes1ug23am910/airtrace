#include "airtrace_pcap.h"

#include <string.h>

static uint16_t read16(const uint8_t *p, bool big)
{
    if (big) return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read32(const uint8_t *p, bool big)
{
    if (big) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | p[3];
    }
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

airtrace_err airtrace_pcap_open(airtrace_pcap *reader, FILE *file)
{
    uint8_t h[24];
    uint32_t magic, network;
    airtrace_pcap result = {0};
    if (reader == NULL) return AIRTRACE_ERR_INVALID;
    memset(reader, 0, sizeof(*reader));
    if (file == NULL) return AIRTRACE_ERR_INVALID;
    if (fread(h, 1, sizeof(h), file) != sizeof(h)) {
        return ferror(file) ? AIRTRACE_ERR_IO : AIRTRACE_ERR_TRUNCATED;
    }
    magic = read32(h, false);
    if (magic == UINT32_C(0xa1b2c3d4)) {
        result.big_endian = false;
    } else if (magic == UINT32_C(0xd4c3b2a1)) {
        result.big_endian = true;
    } else if (magic == UINT32_C(0xa1b23c4d)) {
        result.big_endian = false;
        result.nanosecond = true;
    } else if (magic == UINT32_C(0x4d3cb2a1)) {
        result.big_endian = true;
        result.nanosecond = true;
    } else {
        return AIRTRACE_ERR_UNSUPPORTED;
    }
    if (read16(h + 4, result.big_endian) != 2 ||
        read16(h + 6, result.big_endian) != 4) {
        return AIRTRACE_ERR_UNSUPPORTED;
    }
    result.snaplen = read32(h + 16, result.big_endian);
    if (result.snaplen == 0) return AIRTRACE_ERR_MALFORMED;
    network = read32(h + 20, result.big_endian);
    /* Additional linktype/FCS metadata is not conveyed by the frame API. */
    if (network != AIRTRACE_LINKTYPE_IEEE802_11 &&
        network != AIRTRACE_LINKTYPE_RADIOTAP) {
        return AIRTRACE_ERR_UNSUPPORTED;
    }
    result.linktype = (int)network;
    result.file = file;
    *reader = result;
    return AIRTRACE_OK;
}

airtrace_err airtrace_pcap_next(airtrace_pcap *reader, uint8_t *buf,
                              size_t capacity, airtrace_pcap_record *record)
{
    uint8_t h[16];
    size_t got;
    uint32_t fraction;
    airtrace_pcap_record result = {0};
    airtrace_err error = AIRTRACE_OK;
    if (record == NULL) return AIRTRACE_ERR_INVALID;
    memset(record, 0, sizeof(*record));
    if (reader == NULL || reader->file == NULL || buf == NULL) {
        return AIRTRACE_ERR_INVALID;
    }
    got = fread(h, 1, sizeof(h), reader->file);
    if (got != sizeof(h)) {
        error = ferror(reader->file) ? AIRTRACE_ERR_IO :
                (got == 0 ? AIRTRACE_EOF : AIRTRACE_ERR_TRUNCATED);
        if (error != AIRTRACE_EOF) reader->file = NULL;
        return error;
    }
    result.ts_sec = read32(h, reader->big_endian);
    fraction = read32(h + 4, reader->big_endian);
    result.captured_len = read32(h + 8, reader->big_endian);
    result.original_len = read32(h + 12, reader->big_endian);
    if (fraction >= (reader->nanosecond ? UINT32_C(1000000000) :
                                        UINT32_C(1000000)) ||
        result.captured_len > reader->snaplen ||
        result.captured_len > result.original_len) {
        error = AIRTRACE_ERR_MALFORMED;
    } else if (result.captured_len > capacity) {
        error = AIRTRACE_ERR_CAPACITY;
    } else if (fread(buf, 1, result.captured_len, reader->file) !=
               result.captured_len) {
        error = ferror(reader->file) ? AIRTRACE_ERR_IO : AIRTRACE_ERR_TRUNCATED;
    }
    if (error != AIRTRACE_OK) {
        reader->file = NULL;
        return error;
    }
    result.ts_nsec = reader->nanosecond ? fraction : fraction * UINT32_C(1000);
    *record = result;
    return AIRTRACE_OK;
}
