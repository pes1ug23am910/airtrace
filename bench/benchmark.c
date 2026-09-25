#if defined(__APPLE__)
/* sysctl's Darwin headers require BSD types alongside POSIX timing APIs. */
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "airtrace_pcap.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

typedef struct {
    uint8_t *data;
    size_t length;
} packet;

static double monotonic_seconds(void)
{
    struct timespec now;
#if defined(CLOCK_MONOTONIC)
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1.0;
#else
    if (timespec_get(&now, TIME_UTC) != TIME_UTC) return -1.0;
#endif
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static void cpu_model(char *output, size_t capacity)
{
    snprintf(output, capacity, "unknown");
#if defined(__APPLE__)
    size_t length = capacity;
    if (sysctlbyname("machdep.cpu.brand_string", output, &length, NULL, 0) != 0) {
        length = capacity;
        if (sysctlbyname("hw.model", output, &length, NULL, 0) != 0) {
            snprintf(output, capacity, "unknown");
        }
    }
    output[capacity - 1] = '\0';
#elif defined(__linux__)
    FILE *file = fopen("/proc/cpuinfo", "r");
    char line[512];
    if (file == NULL) return;
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strncmp(line, "model name", 10) == 0 ||
            strncmp(line, "Hardware", 8) == 0) {
            char *value = strchr(line, ':');
            if (value != NULL) {
                ++value;
                while (*value == ' ' || *value == '\t') ++value;
                value[strcspn(value, "\r\n")] = '\0';
                snprintf(output, capacity, "%s", value);
                break;
            }
        }
    }
    fclose(file);
#endif
}

int main(int argc, char **argv)
{
    FILE *input = NULL;
    airtrace_pcap reader;
    airtrace_pcap_record record;
    airtrace_err error;
    packet *packets = NULL;
    size_t count = 0, capacity = 0, i;
    uint8_t *buffer = NULL;
    uintmax_t iterations = 10000, loop, accepted = 0, rejected = 0, checksum = 0;
    double start, elapsed;
    char model[256];
    int result = 1;
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <capture.pcap> [iterations]\n", argv[0]);
        return 2;
    }
    if (argc == 3) {
        char *end;
        errno = 0;
        iterations = strtoumax(argv[2], &end, 10);
        if (errno != 0 || *argv[2] < '0' || *argv[2] > '9' ||
            *end != '\0' || iterations == 0) {
            fprintf(stderr, "iterations must be a positive integer\n");
            return 2;
        }
    }
    input = fopen(argv[1], "rb");
    if (input == NULL) { perror(argv[1]); goto cleanup; }
    error = airtrace_pcap_open(&reader, input);
    if (error != AIRTRACE_OK) {
        fprintf(stderr, "pcap: %s\n", airtrace_strerror(error));
        goto cleanup;
    }
    if (reader.snaplen > UINT32_C(16777216)) {
        fprintf(stderr, "benchmark limits snaplen to 16 MiB\n");
        goto cleanup;
    }
    buffer = malloc(reader.snaplen);
    if (buffer == NULL) goto cleanup;
    while ((error = airtrace_pcap_next(&reader, buffer, reader.snaplen, &record)) == AIRTRACE_OK) {
        if (count == capacity) {
            size_t next_capacity = capacity == 0 ? 256 : capacity * 2;
            packet *grown;
            if (next_capacity < capacity || next_capacity > SIZE_MAX / sizeof(*packets)) {
                fprintf(stderr, "too many packets\n");
                goto cleanup;
            }
            grown = realloc(packets, next_capacity * sizeof(*packets));
            if (grown == NULL) goto cleanup;
            packets = grown;
            capacity = next_capacity;
        }
        packets[count].data = malloc(record.captured_len == 0 ? 1 : record.captured_len);
        if (packets[count].data == NULL) goto cleanup;
        packets[count].length = record.captured_len;
        memcpy(packets[count].data, buffer, record.captured_len);
        ++count;
    }
    if (error != AIRTRACE_EOF || count == 0 || iterations > UINTMAX_MAX / count) {
        fprintf(stderr, "invalid capture or iteration count: %s\n", airtrace_strerror(error));
        goto cleanup;
    }
    if (fclose(input) != 0) { input = NULL; goto cleanup; }
    input = NULL;
    free(buffer);
    buffer = NULL;
    cpu_model(model, sizeof(model));
    /* Warm caches before measuring. All allocation and I/O is outside the loop. */
    for (i = 0; i < count; ++i) {
        airtrace_frame frame;
        (void)airtrace_parse_frame(packets[i].data, packets[i].length, reader.linktype, &frame);
    }
    start = monotonic_seconds();
    if (start < 0) goto cleanup;
    for (loop = 0; loop < iterations; ++loop) {
        for (i = 0; i < count; ++i) {
            airtrace_frame frame;
            error = airtrace_parse_frame(packets[i].data, packets[i].length, reader.linktype, &frame);
            if (error == AIRTRACE_OK) {
                ++accepted;
                checksum += frame.frame_control + frame.seq + frame.ie_count;
            } else {
                ++rejected;
                checksum += (unsigned int)error;
            }
        }
    }
    elapsed = monotonic_seconds() - start;
    if (elapsed <= 0) { fprintf(stderr, "timer did not advance\n"); goto cleanup; }
    printf("CPU: %s\nCapture: %s\nFrames: %zu\nIterations: %" PRIuMAX "\n"
           "Parsed: %" PRIuMAX "\nRejected: %" PRIuMAX "\n"
           "Elapsed: %.6f s\nFrames/s: %.0f\nChecksum: %" PRIuMAX "\n",
           model, argv[1], count, iterations, accepted, rejected, elapsed,
           (double)(accepted + rejected) / elapsed, checksum);
    result = 0;
cleanup:
    if (input != NULL) fclose(input);
    free(buffer);
    for (i = 0; i < count; ++i) free(packets[i].data);
    free(packets);
    return result;
}
