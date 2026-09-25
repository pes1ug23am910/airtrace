#include "airtrace.h"

#include <assert.h>
#include <string.h>

/* Byte 0 selects encapsulation: 0 = raw 802.11, 1 = radiotap. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    airtrace_frame frame;
    airtrace_err error;
    int linktype = AIRTRACE_LINKTYPE_IEEE802_11;
    if (size != 0) {
        linktype = (data[0] & 1u) ? AIRTRACE_LINKTYPE_RADIOTAP :
                                  AIRTRACE_LINKTYPE_IEEE802_11;
        ++data;
        --size;
    }
    memset(&frame, 0xa5, sizeof(frame));
    error = airtrace_parse_frame(data, size, linktype, &frame);
    if (error == AIRTRACE_OK) {
        size_t i;
        assert(frame.addr_count <= 4);
        assert(frame.ie_count <= AIRTRACE_MAX_IES);
        assert(frame.ssid_len <= sizeof(frame.ssid));
        assert(frame.header_len <= size);
        for (i = 0; i < frame.ie_count; ++i) {
            assert(frame.ies[i].offset <= size);
            assert(frame.ies[i].len <= size - frame.ies[i].offset);
        }
    } else {
        const unsigned char *bytes = (const unsigned char *)&frame;
        size_t i;
        for (i = 0; i < sizeof(frame); ++i) assert(bytes[i] == 0);
    }
    return 0;
}
