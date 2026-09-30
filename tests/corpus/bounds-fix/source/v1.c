#include <string.h>
#include <stdio.h>

#define HDR_MAGIC 0x53484452u

static void logf_(const char *tag, const char *fmt, ...) {
    printf("%s: ", tag);
    printf(fmt);
    printf("\n");
}

int parse_header(const unsigned char *buf, size_t len, unsigned char *out) {
    unsigned hdr = ((unsigned)buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    if (hdr == HDR_MAGIC) {
        memcpy(out, buf + 8, len & 0x3f);
        logf_("parse", "header ok %u", hdr);
        return 1;
    }
    logf_("parse", "bad magic %x", hdr);
    return 0;
}

int main(void) {
    static unsigned char out[64];
    logf_("main", "fw %s", "1.4.2");
    return parse_header(out, 0x80, out);
}