#include "airtrace_pcap.h"

#include <inttypes.h>
#include <stdlib.h>

/* Usage: airtrace_seed <capture.pcap> <existing-directory> <prefix> */
int main(int argc, char **argv)
{
    FILE *input;
    airtrace_pcap reader;
    airtrace_pcap_record record;
    airtrace_err error;
    uint8_t *buffer;
    size_t count = 0;
    if (argc != 4) {
        fprintf(stderr, "usage: %s <capture.pcap> <existing-directory> <prefix>\n", argv[0]);
        return 2;
    }
    input = fopen(argv[1], "rb");
    if (input == NULL) { perror(argv[1]); return 1; }
    error = airtrace_pcap_open(&reader, input);
    if (error != AIRTRACE_OK) {
        fprintf(stderr, "pcap: %s\n", airtrace_strerror(error));
        fclose(input);
        return 1;
    }
    if (reader.snaplen > UINT32_C(16777216)) {
        fprintf(stderr, "seed extractor limits snaplen to 16 MiB\n");
        fclose(input);
        return 1;
    }
    buffer = malloc(reader.snaplen);
    if (buffer == NULL) { fclose(input); return 1; }
    while ((error = airtrace_pcap_next(&reader, buffer, reader.snaplen, &record)) == AIRTRACE_OK) {
        char path[4096];
        FILE *output;
        int written = snprintf(path, sizeof(path), "%s/%s-%06zu", argv[2], argv[3], count);
        if (written < 0 || (size_t)written >= sizeof(path)) {
            error = AIRTRACE_ERR_CAPACITY;
            break;
        }
        output = fopen(path, "wb");
        if (output == NULL) { error = AIRTRACE_ERR_IO; break; }
        if (fputc(reader.linktype == AIRTRACE_LINKTYPE_RADIOTAP ? 1 : 0, output) == EOF ||
            fwrite(buffer, 1, record.captured_len, output) != record.captured_len) {
            error = AIRTRACE_ERR_IO;
        }
        if (fclose(output) != 0) error = AIRTRACE_ERR_IO;
        if (error != AIRTRACE_OK) break;
        ++count;
    }
    free(buffer);
    if (fclose(input) != 0 && error == AIRTRACE_EOF) error = AIRTRACE_ERR_IO;
    if (error != AIRTRACE_EOF) {
        fprintf(stderr, "seed extraction: %s\n", airtrace_strerror(error));
        return 1;
    }
    printf("Extracted %zu frame seeds from %s\n", count, argv[1]);
    return 0;
}
