#include "tls_peek.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>

static uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

static int has_otpe_in_alpn(const uint8_t* p, size_t len) {
    if (len < 2) return 0;
    uint16_t list_len = rd16(p);
    if (list_len + 2 > len) return 0;
    size_t pos = 2;
    while (pos + 1 < len && pos < (size_t)(2 + list_len)) {
        uint8_t alen = p[pos];
        if (pos + 1 + alen > len) return 0;
        if (alen == 4 && memcmp(p + pos + 1, "0tpe", 4) == 0) return 1;
        pos += 1 + alen;
    }
    return 0;
}

int tls_parse_clienthello(const uint8_t* buf, size_t buf_len,
                          char* sni_out, size_t sni_size,
                          int* has_otpe_alpn) {
    if (sni_size) sni_out[0] = '\0';
    *has_otpe_alpn = 0;

    if (buf_len < 44) return -1;
    if (buf[0] != 0x16) return -1;
    if (buf[5] != 0x01) return -1;

    uint8_t sid_len = buf[43];
    if (sid_len > 32) return -1;
    if (buf_len < (size_t)(44 + sid_len)) return -1;

    size_t pos = 44 + sid_len;
    if (buf_len < pos + 2) return -1;
    uint16_t cs_len = rd16(buf + pos);
    pos += 2 + cs_len;

    if (buf_len < pos + 1) return -1;
    uint8_t cm_len = buf[pos];
    pos += 1 + cm_len;

    if (buf_len < pos + 2) return -1;
    uint16_t ext_total = rd16(buf + pos);
    pos += 2;
    if (buf_len < pos + ext_total) return -1;

    size_t ext_end = pos + ext_total;
    while (pos + 4 <= ext_end) {
        uint16_t et = rd16(buf + pos);
        uint16_t el = rd16(buf + pos + 2);
        pos += 4;
        if (pos + el > ext_end) return -1;

        if (et == 0x0000 && el >= 5 && sni_size > 0) {
            uint16_t list_len = rd16(buf + pos);
            if (list_len >= 3 && (size_t)(list_len + 2) <= el) {
                uint8_t nt = buf[pos + 2];
                uint16_t nl = rd16(buf + pos + 3);
                if (nt == 0 && 5 + nl <= el && nl < sni_size) {
                    memcpy(sni_out, buf + pos + 5, nl);
                    sni_out[nl] = '\0';
                }
            }
        } else if (et == 0x0010) {
            if (has_otpe_in_alpn(buf + pos, el)) {
                *has_otpe_alpn = 1;
            }
        }
        pos += el;
    }
    return 0;
}

int tls_peek_clienthello(int fd, char* sni_out, size_t sni_size, int* has_otpe_alpn) {
    uint8_t buf[16384];
    ssize_t got = 0;
    int waited_ms = 0;

    if (sni_size) sni_out[0] = '\0';
    *has_otpe_alpn = 0;

    while (waited_ms < 3000) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int r = poll(&pfd, 1, 100);
        if (r < 0) return -1;
        if (r == 0) { waited_ms += 100; continue; }

        ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK);
        if (n <= 0) return -1;
        if (n > got) { got = n; waited_ms = 0; }
        else { usleep(10000); waited_ms += 10; continue; }

        if (got < 44) continue;
        uint8_t sid_len = buf[43];
        if (sid_len > 32) return -1;
        if (got < (ssize_t)(44 + sid_len)) continue;

        size_t pos = 44 + sid_len;
        if (got < (ssize_t)(pos + 2)) continue;
        uint16_t cs_len = rd16(buf + pos);
        if (got < (ssize_t)(pos + 2 + cs_len)) continue;

        return tls_parse_clienthello(buf, (size_t)got, sni_out, sni_size, has_otpe_alpn);
    }
    return -1;
}