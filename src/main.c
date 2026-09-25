#include "airtrace.h"
#include "airtrace_pcap.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKET_CAPACITY (1024u * 1024u)
#define MAX_BSSIDS 1024u
#define MAX_HANDSHAKES 4096u

typedef struct {
    uint8_t bssid[6], ssid[32], ssid_len;
    bool has_ssid, has_channel;
    uint16_t channel;
    uint64_t frames, rssi_count;
    int64_t rssi_sum;
    int16_t rssi_min, rssi_max;
} bssid_stats;

typedef struct {
    uint8_t client[6], bssid[6], mask;
    uint64_t messages[4];
} handshake_stats;

typedef struct {
    uint64_t frames, parsed, errors, subtypes[4][16];
    uint64_t reasons[2][65536];
    bssid_stats bssids[MAX_BSSIDS];
    handshake_stats handshakes[MAX_HANDSHAKES];
    size_t bssid_count, handshake_count;
    bool bssid_overflow, handshake_overflow;
} capture_stats;

static uint8_t packet[PACKET_CAPACITY];
static capture_stats stats;

/* SSIDs are arbitrary octets. ASCII is literal, other bytes map to U+00xx. */
static void json_bytes(FILE *stream, const uint8_t *bytes, size_t length)
{
    size_t i;
    fputc('"', stream);
    for (i = 0; i < length; ++i) {
        unsigned int byte = bytes[i];
        if (byte == '"' || byte == '\\') {
            fputc('\\', stream);
            fputc((int)byte, stream);
        } else if (byte >= 32u && byte <= 126u) {
            fputc((int)byte, stream);
        } else {
            fprintf(stream, "\\u%04x", byte);
        }
    }
    fputc('"', stream);
}

static void mac(FILE *stream, const uint8_t address[6])
{
    fprintf(stream, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned)address[0],
            (unsigned)address[1], (unsigned)address[2], (unsigned)address[3],
            (unsigned)address[4], (unsigned)address[5]);
}

static void optional_number(FILE *stream, bool present, uint64_t value)
{
    if (present) fprintf(stream, "%" PRIu64, value);
    else fputs("null", stream);
}

static const char *ie_name(uint8_t id)
{
    switch (id) {
    case 0: return "ssid";
    case 1: return "supported_rates";
    case 3: return "ds_parameter_set";
    case 45: return "ht_capabilities";
    case 48: return "rsn";
    case 191: return "vht_capabilities";
    default: return "unknown";
    }
}

static void print_frame(const airtrace_frame *frame, const airtrace_pcap_record *record,
                        uint64_t number)
{
    size_t i;
    const char *types[] = {"management", "control", "data", "extension"};
    printf("{\"frame\":%" PRIu64 ",\"ts\":%" PRIu32 ".%09" PRIu32 ",\"rssi_dbm\":",
           number, record->ts_sec, record->ts_nsec);
    if (frame->has_rssi) printf("%d", (int)frame->rssi_dbm);
    else fputs("null", stdout);
    fputs(",\"freq\":", stdout);
    optional_number(stdout, frame->has_channel, frame->freq);
    fputs(",\"channel\":", stdout);
    optional_number(stdout, frame->channel != 0, frame->channel);
    printf(",\"type\":\"%s\",\"subtype\":\"%s\",\"type_id\":%u,\"subtype_id\":%u,\"addrs\":[",
           types[frame->type], airtrace_subtype_name(frame->type, frame->subtype),
           (unsigned)frame->type, (unsigned)frame->subtype);
    for (i = 0; i < frame->addr_count; ++i) {
        if (i != 0) fputc(',', stdout);
        fputc('"', stdout); mac(stdout, frame->addrs[i]); fputc('"', stdout);
    }
    fputs("],\"bssid\":", stdout);
    if (frame->has_bssid) {
        fputc('"', stdout); mac(stdout, frame->bssid); fputc('"', stdout);
    } else fputs("null", stdout);
    fputs(",\"ssid\":", stdout);
    if (frame->has_ssid) json_bytes(stdout, frame->ssid, frame->ssid_len);
    else fputs("null", stdout);
    fputs(",\"seq\":", stdout);
    optional_number(stdout, frame->has_seq, frame->seq);
    printf(",\"retry\":%s,\"protected\":%s,\"status_code\":",
           frame->retry ? "true" : "false", frame->protected_frame ? "true" : "false");
    optional_number(stdout, frame->has_status, frame->status_code);
    fputs(",\"reason_code\":", stdout);
    optional_number(stdout, frame->has_reason, frame->reason_code);
    fputs(",\"eapol_msg\":", stdout);
    optional_number(stdout, frame->eapol_msg != 0, frame->eapol_msg);
    fputs(",\"ie_summary\":[", stdout);
    for (i = 0; i < frame->ie_count; ++i) {
        printf("%s{\"id\":%u,\"name\":\"%s\",\"len\":%u}", i != 0 ? "," : "",
               (unsigned)frame->ies[i].id, ie_name(frame->ies[i].id),
               (unsigned)frame->ies[i].len);
    }
    fputs("]}\n", stdout);
}

static bool unicast(const uint8_t address[6])
{
    static const uint8_t zero[6] = {0};
    return (address[0] & 1u) == 0 && memcmp(address, zero, 6) != 0;
}

static void add_bssid(const airtrace_frame *frame)
{
    size_t i;
    bssid_stats *entry;
    if (!frame->has_bssid || !unicast(frame->bssid)) return;
    for (i = 0; i < stats.bssid_count; ++i)
        if (memcmp(stats.bssids[i].bssid, frame->bssid, 6) == 0) break;
    if (i == stats.bssid_count) {
        if (i == MAX_BSSIDS) { stats.bssid_overflow = true; return; }
        memcpy(stats.bssids[i].bssid, frame->bssid, 6);
        ++stats.bssid_count;
    }
    entry = &stats.bssids[i];
    ++entry->frames;
    /* Retain a revealed SSID when subsequent beacons advertise a hidden SSID. */
    if (frame->has_ssid && (!entry->has_ssid || frame->ssid_len != 0)) {
        memcpy(entry->ssid, frame->ssid, frame->ssid_len);
        entry->ssid_len = frame->ssid_len;
        entry->has_ssid = true;
    }
    if (frame->channel != 0) {
        entry->has_channel = true;
        entry->channel = frame->channel;
    }
    if (frame->has_rssi) {
        if (entry->rssi_count == 0 || frame->rssi_dbm < entry->rssi_min)
            entry->rssi_min = frame->rssi_dbm;
        if (entry->rssi_count == 0 || frame->rssi_dbm > entry->rssi_max)
            entry->rssi_max = frame->rssi_dbm;
        entry->rssi_sum += frame->rssi_dbm;
        ++entry->rssi_count;
    }
}

static void add_handshake(const airtrace_frame *frame)
{
    const uint8_t *client;
    handshake_stats *entry;
    size_t i;
    if (frame->eapol_msg == 0 || !frame->has_bssid || frame->addr_count < 2) return;
    if (memcmp(frame->addrs[0], frame->bssid, 6) == 0) client = frame->addrs[1];
    else if (memcmp(frame->addrs[1], frame->bssid, 6) == 0) client = frame->addrs[0];
    else return;
    if (!unicast(client) || !unicast(frame->bssid)) return;
    for (i = 0; i < stats.handshake_count; ++i) {
        entry = &stats.handshakes[i];
        if (memcmp(entry->bssid, frame->bssid, 6) == 0 &&
            memcmp(entry->client, client, 6) == 0) break;
    }
    if (i == stats.handshake_count) {
        if (i == MAX_HANDSHAKES) { stats.handshake_overflow = true; return; }
        memcpy(stats.handshakes[i].client, client, 6);
        memcpy(stats.handshakes[i].bssid, frame->bssid, 6);
        ++stats.handshake_count;
    }
    entry = &stats.handshakes[i];
    entry->mask |= (uint8_t)(1u << (frame->eapol_msg - 1u));
    ++entry->messages[frame->eapol_msg - 1u];
}

static void add_stats(const airtrace_frame *frame)
{
    ++stats.parsed;
    ++stats.subtypes[frame->type][frame->subtype];
    if (frame->type == 0 && frame->has_reason) {
        if (frame->subtype == 10) ++stats.reasons[0][frame->reason_code];
        if (frame->subtype == 12) ++stats.reasons[1][frame->reason_code];
    }
    add_bssid(frame);
    add_handshake(frame);
}

static void print_stats(FILE *stream)
{
    unsigned int type, subtype, reason;
    size_t i, message;
    fprintf(stream, "Frames: %" PRIu64 "  parsed: %" PRIu64 "  errors: %" PRIu64 "\n",
            stats.frames, stats.parsed, stats.errors);
    fputs("Subtypes:\n", stream);
    for (type = 0; type < 4; ++type) for (subtype = 0; subtype < 16; ++subtype)
        if (stats.subtypes[type][subtype] != 0)
            fprintf(stream, "  %u/%u %-24s %" PRIu64 "\n", type, subtype,
                    airtrace_subtype_name((uint8_t)type, (uint8_t)subtype),
                    stats.subtypes[type][subtype]);
    fputs("BSSIDs (last observed channel; observed RSSI):\n", stream);
    for (i = 0; i < stats.bssid_count; ++i) {
        const bssid_stats *entry = &stats.bssids[i];
        fputs("  ", stream); mac(stream, entry->bssid); fputs(" ssid=", stream);
        if (entry->has_ssid) json_bytes(stream, entry->ssid, entry->ssid_len);
        else fputs("unknown", stream);
        fputs(" channel=", stream);
        if (entry->has_channel) fprintf(stream, "%u", (unsigned)entry->channel);
        else fputs("unknown", stream);
        fprintf(stream, " frames=%" PRIu64 " rssi=", entry->frames);
        if (entry->rssi_count != 0)
            fprintf(stream, "%.1f dBm (min %d, max %d, n=%" PRIu64 ")",
                    (double)entry->rssi_sum / (double)entry->rssi_count,
                    (int)entry->rssi_min, (int)entry->rssi_max, entry->rssi_count);
        else fputs("unknown", stream);
        fputc('\n', stream);
    }
    fputs("Deauth/disassoc reasons:\n", stream);
    for (type = 0; type < 2; ++type) for (reason = 0; reason < 65536u; ++reason)
        if (stats.reasons[type][reason] != 0)
            fprintf(stream, "  %s reason=%u count=%" PRIu64 "\n",
                    type == 0 ? "disassoc" : "deauth", reason, stats.reasons[type][reason]);
    fputs("4-way handshakes (messages observed across capture, including retries):\n", stream);
    for (i = 0; i < stats.handshake_count; ++i) {
        const handshake_stats *entry = &stats.handshakes[i];
        fputs("  client=", stream); mac(stream, entry->client);
        fputs(" bssid=", stream); mac(stream, entry->bssid);
        fputs(" observed=", stream);
        for (message = 0; message < 4; ++message)
            if ((entry->mask & (1u << message)) != 0) fprintf(stream, "%zu", message + 1);
        fprintf(stream, " complete=%s counts=%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                entry->mask == 15 ? "yes" : "no", entry->messages[0], entry->messages[1],
                entry->messages[2], entry->messages[3]);
    }
    if (stats.bssid_overflow || stats.handshake_overflow)
        fputs("ERROR: statistics table capacity exceeded; summary is incomplete.\n", stream);
}

static void usage(FILE *stream)
{
    fputs("Usage: airtrace parse <file.pcap> [--jsonl] [--stats]\n"
          "       airtrace --version\n"
          "Default output is JSONL. --stats alone prints a text summary.\n"
          "With both options, JSONL goes to stdout and statistics to stderr.\n", stream);
}

int main(int argc, char **argv)
{
    FILE *file;
    airtrace_pcap reader;
    airtrace_pcap_record record;
    airtrace_frame frame;
    airtrace_err err;
    bool jsonl = false, want_stats = false;
    int i, result = EXIT_SUCCESS;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("airtrace " AIRTRACE_VERSION); return EXIT_SUCCESS;
    }
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(stdout); return EXIT_SUCCESS;
    }
    if (argc < 3 || strcmp(argv[1], "parse") != 0) { usage(stderr); return 2; }
    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--jsonl") == 0) jsonl = true;
        else if (strcmp(argv[i], "--stats") == 0) want_stats = true;
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(stderr); return 2; }
    }
    if (!want_stats) jsonl = true;
    file = fopen(argv[2], "rb");
    if (file == NULL) { perror(argv[2]); return EXIT_FAILURE; }
    err = airtrace_pcap_open(&reader, file);
    if (err != AIRTRACE_OK) {
        fprintf(stderr, "%s: %s\n", argv[2], airtrace_strerror(err));
        fclose(file); return EXIT_FAILURE;
    }
    while ((err = airtrace_pcap_next(&reader, packet, sizeof(packet), &record)) == AIRTRACE_OK) {
        ++stats.frames;
        err = airtrace_parse_frame(packet, record.captured_len, reader.linktype, &frame);
        if (err != AIRTRACE_OK) {
            ++stats.errors;
            result = EXIT_FAILURE;
            if (jsonl)
                printf("{\"frame\":%" PRIu64 ",\"ts\":%" PRIu32 ".%09" PRIu32 ",\"error\":\"%s\"}\n",
                       stats.frames, record.ts_sec, record.ts_nsec, airtrace_strerror(err));
            fprintf(stderr, "Frame %" PRIu64 ": %s\n", stats.frames, airtrace_strerror(err));
        } else {
            if (want_stats) add_stats(&frame);
            if (jsonl) print_frame(&frame, &record, stats.frames);
        }
    }
    if (err != AIRTRACE_EOF) {
        fprintf(stderr, "Pcap record after frame %" PRIu64 ": %s\n", stats.frames, airtrace_strerror(err));
        result = EXIT_FAILURE;
    }
    if (want_stats) print_stats(jsonl ? stderr : stdout);
    if (stats.bssid_overflow || stats.handshake_overflow) result = EXIT_FAILURE;
    if (fclose(file) != 0) { perror("close capture"); result = EXIT_FAILURE; }
    if (fflush(stdout) != 0 || ferror(stdout) || ferror(stderr)) result = EXIT_FAILURE;
    return result;
}
