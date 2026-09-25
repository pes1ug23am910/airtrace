#ifndef AIRTRACE_PCAP_H
#define AIRTRACE_PCAP_H
#include "airtrace.h"
#include <stdio.h>

typedef struct {
    FILE *file;
    bool big_endian, nanosecond;
    uint32_t snaplen;
    int linktype;
} airtrace_pcap;

typedef struct {
    uint32_t ts_sec, ts_nsec;
    uint32_t captured_len, original_len;
} airtrace_pcap_record;

/* FILE remains owned by caller. Record read/format/capacity errors are terminal
 * and clear reader->file; reopen to reuse. EOF does not invalidate the reader. */
airtrace_err airtrace_pcap_open(airtrace_pcap *reader, FILE *file);
airtrace_err airtrace_pcap_next(airtrace_pcap *reader, uint8_t *buf, size_t capacity,
                              airtrace_pcap_record *record);
#endif
