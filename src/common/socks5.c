#include "socks5.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>

#define SOCKS5_TIMEOUT_MS 10000

static int read_full(int fd, void* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int r = poll(&pfd, 1, SOCKS5_TIMEOUT_MS);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "socks5: poll read errno=%d\n", errno);
            return -1;
        }
        if (r == 0) {
            fprintf(stderr, "socks5: read timeout after %zu/%zu bytes\n", got, n);
            return -1;
        }
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            fprintf(stderr, "socks5: poll error revents=0x%x\n", pfd.revents);
            return -1;
        }
        ssize_t r2 = read(fd, (char*)buf + got, n - got);
        if (r2 < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "socks5: read errno=%d\n", errno);
            return -1;
        }
        if (r2 == 0) {
            fprintf(stderr, "socks5: eof after %zu/%zu bytes\n", got, n);
            return -1;
        }
        got += (size_t)r2;
    }
    return 0;
}

static int write_full(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "socks5: write errno=%d\n", errno);
            return -1;
        }
        if (w == 0) {
            fprintf(stderr, "socks5: write returned 0\n");
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

int socks5_handshake(int fd, uint8_t* cmd_out, char* out_host, size_t host_size,
                     uint16_t* out_port, uint16_t udp_listen_port) {
    uint8_t buf[512];

    if (read_full(fd, buf, 2) < 0) {
        fprintf(stderr, "socks5: greeting VER/NMETHODS failed\n");
        return -1;
    }
    if (buf[0] != 0x05) {
        fprintf(stderr, "socks5: bad VER=0x%02x\n", buf[0]);
        return -1;
    }
    uint8_t nmethods = buf[1];
    if (nmethods == 0 || nmethods > 8) {
        fprintf(stderr, "socks5: bad NMETHODS=%u\n", nmethods);
        return -1;
    }
    if (read_full(fd, buf, nmethods) < 0) {
        fprintf(stderr, "socks5: METHODS failed\n");
        return -1;
    }

    uint8_t greeting[2] = {0x05, 0x00};
    if (write_full(fd, greeting, 2) < 0) {
        fprintf(stderr, "socks5: greeting reply failed\n");
        return -1;
    }

    if (read_full(fd, buf, 4) < 0) {
        fprintf(stderr, "socks5: request header failed\n");
        return -1;
    }
    if (buf[0] != 0x05) {
        fprintf(stderr, "socks5: bad request VER=0x%02x\n", buf[0]);
        return -1;
    }
    uint8_t cmd = buf[1];
    if (cmd != 0x01 && cmd != 0x03) {
        fprintf(stderr, "socks5: unsupported CMD=0x%02x\n", cmd);
        uint8_t rep[10] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        write_full(fd, rep, 10);
        return -1;
    }
    uint8_t atyp = buf[3];

    out_host[0] = '\0';
    if (atyp == 0x01) {
        if (read_full(fd, buf, 4) < 0) return -1;
        snprintf(out_host, host_size, "%u.%u.%u.%u", buf[0], buf[1], buf[2], buf[3]);
    } else if (atyp == 0x03) {
        uint8_t len = 0;
        if (read_full(fd, &len, 1) < 0) return -1;
        if (len == 0 || len >= host_size) return -1;
        if (read_full(fd, buf, len) < 0) return -1;
        memcpy(out_host, buf, len);
        out_host[len] = '\0';
    } else if (atyp == 0x04) {
        if (read_full(fd, buf, 16) < 0) return -1;
        snprintf(out_host, host_size,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                 buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
    } else {
        fprintf(stderr, "socks5: unknown ATYP=0x%02x\n", atyp);
        return -1;
    }

    uint8_t port_buf[2];
    if (read_full(fd, port_buf, 2) < 0) {
        fprintf(stderr, "socks5: port read failed\n");
        return -1;
    }
    *out_port = (uint16_t)((port_buf[0] << 8) | port_buf[1]);

    uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0};
    if (cmd == 0x03) {
        reply[8] = (uint8_t)((udp_listen_port >> 8) & 0xFF);
        reply[9] = (uint8_t)(udp_listen_port & 0xFF);
    }
    if (write_full(fd, reply, 10) < 0) {
        fprintf(stderr, "socks5: final reply failed\n");
        return -1;
    }

    *cmd_out = cmd;
    return 0;
}