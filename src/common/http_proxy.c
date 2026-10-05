#include "http_proxy.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <ctype.h>

#define HTTP_HANDSHAKE_TIMEOUT_MS 10000
#define HTTP_MAX_LINE 8192

static int read_byte_timeout(int fd, uint8_t* out) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    for (;;) {
        int r = poll(&pfd, 1, HTTP_HANDSHAKE_TIMEOUT_MS);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        ssize_t n = read(fd, out, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        return 0;
    }
}

static int write_full(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int read_line(int fd, char* buf, size_t buf_size) {
    size_t i = 0;
    for (;;) {
        if (i + 1 >= buf_size) return -1;
        uint8_t c;
        if (read_byte_timeout(fd, &c) < 0) return -1;
        if (c == '\r') {
            uint8_t lf;
            if (read_byte_timeout(fd, &lf) < 0) return -1;
            if (lf != '\n') return -1;
            buf[i] = '\0';
            return (int)i;
        }
        buf[i++] = (char)c;
    }
}

int http_connect_handshake(int fd, char* out_host, size_t host_size, uint16_t* out_port) {
    char line[HTTP_MAX_LINE];
    int len = read_line(fd, line, sizeof(line));
    if (len <= 0) {
        fprintf(stderr, "http: failed to read request line\n");
        return -1;
    }

    const char* p = line;
    if (strncmp(p, "CONNECT ", 8) != 0) {
        fprintf(stderr, "http: method not CONNECT: %.40s\n", line);
        const char* resp = "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n";
        write_full(fd, resp, strlen(resp));
        return -1;
    }
    p += 8;

    const char* space = strchr(p, ' ');
    if (!space) {
        fprintf(stderr, "http: malformed CONNECT line\n");
        return -1;
    }

    size_t hp_len = (size_t)(space - p);
    if (hp_len == 0 || hp_len >= 256) {
        fprintf(stderr, "http: bad host:port length\n");
        return -1;
    }

    char hostport[256];
    memcpy(hostport, p, hp_len);
    hostport[hp_len] = '\0';

    char* host = hostport;
    uint16_t port = 0;

    if (hostport[0] == '[') {
        char* close = strchr(hostport, ']');
        if (!close) {
            fprintf(stderr, "http: bad IPv6 form\n");
            return -1;
        }
        *close = '\0';
        host = hostport + 1;
        if (*(close + 1) != ':') {
            fprintf(stderr, "http: missing port after ]\n");
            return -1;
        }
        port = (uint16_t)atoi(close + 2);
    } else {
        char* colon = strrchr(hostport, ':');
        if (!colon) {
            fprintf(stderr, "http: missing port\n");
            return -1;
        }
        *colon = '\0';
        host = hostport;
        port = (uint16_t)atoi(colon + 1);
    }

    if (port == 0 || strlen(host) == 0 || strlen(host) >= host_size) {
        fprintf(stderr, "http: bad host/port\n");
        return -1;
    }
    strcpy(out_host, host);
    *out_port = port;

    for (;;) {
        len = read_line(fd, line, sizeof(line));
        if (len < 0) {
            fprintf(stderr, "http: failed to read headers\n");
            return -1;
        }
        if (len == 0) break;
    }

    const char* ok = "HTTP/1.1 200 Connection established\r\n\r\n";
    if (write_full(fd, ok, strlen(ok)) < 0) {
        fprintf(stderr, "http: failed to send 200\n");
        return -1;
    }

    return 0;
}