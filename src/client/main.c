#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "protocol.h"
#include "relay.h"
#include "tls.h"
#include "socks5.h"
#include "http_proxy.h"
#include "crypto.h"
#include "config.h"

static otpe_client_config_t g_cfg;
static uint8_t g_token[OTPE_TOKEN_SIZE];
static void* g_server_pubkey = NULL;
static uint16_t g_udp_port = 0;

static int connect_server(void) {
    int sock = otpe_connect_timeout(g_cfg.server_ip, g_cfg.server_port, 5000);
    if (sock < 0) return -1;
    otpe_set_tcp_nodelay(sock);
    return sock;
}

static int send_connect_request(otpe_tls_t* tls, const char* host, uint16_t port) {
    size_t host_len = strlen(host);
    size_t payload_len = 2 + host_len;

    otpe_header_t h;
    h.version = OTPE_VERSION;
    h.command = OTPE_CMD_CONNECT;
    h.flags = 0;
    h.reserved = 0;
    h.length = (uint16_t)payload_len;
    h.checksum = 0;
    memcpy(h.token, g_token, OTPE_TOKEN_SIZE);

    uint8_t buf[OTPE_HEADER_SIZE + 512];
    if (!otpe_encode_header(&h, buf, OTPE_HEADER_SIZE)) return -1;

    buf[OTPE_HEADER_SIZE]     = (uint8_t)((port >> 8) & 0xFF);
    buf[OTPE_HEADER_SIZE + 1] = (uint8_t)(port & 0xFF);
    memcpy(buf + OTPE_HEADER_SIZE + 2, host, host_len);

    ssize_t sent = otpe_tls_send(tls, buf, OTPE_HEADER_SIZE + payload_len);
    return sent == (ssize_t)(OTPE_HEADER_SIZE + payload_len) ? 0 : -1;
}

static void establish_tunnel(int browser_fd, const char* host, uint16_t port, const char* tag) {
    int server_fd = connect_server();
    if (server_fd < 0) {
        fprintf(stderr, "[%s tid %lu] connect_server failed for %s:%u (errno=%d)\n",
                tag, (unsigned long)pthread_self(), host, port, errno);
        close(browser_fd);
        return;
    }

    otpe_tls_t* tls = otpe_tls_client(server_fd, g_cfg.sni);
    if (!tls) {
        fprintf(stderr, "[%s tid %lu] TLS handshake failed for %s:%u\n",
                tag, (unsigned long)pthread_self(), host, port);
        close(server_fd);
        close(browser_fd);
        return;
    }

    if (send_connect_request(tls, host, port) < 0) {
        fprintf(stderr, "[%s tid %lu] CONNECT request failed for %s:%u\n",
                tag, (unsigned long)pthread_self(), host, port);
        otpe_tls_free(tls);
        close(server_fd);
        close(browser_fd);
        return;
    }

    long total = otpe_relay_tls_bidirectional(tls, browser_fd);

    if (total < 0) {
        fprintf(stderr, "[%s tid %lu] relay error for %s:%u\n",
                tag, (unsigned long)pthread_self(), host, port);
    }

    printf("[%s tid %lu] closed %s:%u (%ld bytes)\n",
           tag, (unsigned long)pthread_self(), host, port, total);
    otpe_tls_free(tls);
    close(server_fd);
    close(browser_fd);
}

static void* socks5_thread(void* arg) {
    int fd = (int)(intptr_t)arg;
    otpe_set_tcp_nodelay(fd);

    uint8_t cmd = 0;
    char host[256] = {0};
    uint16_t port = 0;
    if (socks5_handshake(fd, &cmd, host, sizeof(host), &port, g_udp_port) < 0) {
        close(fd);
        return NULL;
    }

    if (cmd == 0x01) {
        printf("[SOCKS5 tid %lu] CONNECT %s:%u\n", (unsigned long)pthread_self(), host, port);
        establish_tunnel(fd, host, port, "SOCKS5");
    } else if (cmd == 0x03) {
        printf("[SOCKS5 tid %lu] UDP ASSOCIATE -> 127.0.0.1:%u\n",
               (unsigned long)pthread_self(), g_udp_port);
        uint8_t b;
        while (read(fd, &b, 1) > 0) {}
        printf("[SOCKS5 tid %lu] UDP session closed\n", (unsigned long)pthread_self());
    }
    close(fd);
    return NULL;
}

static void* http_thread(void* arg) {
    int fd = (int)(intptr_t)arg;
    otpe_set_tcp_nodelay(fd);

    char host[256];
    uint16_t port = 0;
    if (http_connect_handshake(fd, host, sizeof(host), &port) < 0) {
        close(fd);
        return NULL;
    }

    printf("[HTTP tid %lu] %s:%u\n", (unsigned long)pthread_self(), host, port);
    establish_tunnel(fd, host, port, "HTTP");
    return NULL;
}

static int make_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 128) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static ssize_t udp_recv_tls_payload(otpe_tls_t* tls, otpe_header_t* h, uint8_t* out, size_t out_size) {
    uint8_t hb[OTPE_HEADER_SIZE];
    ssize_t got = 0;
    while (got < OTPE_HEADER_SIZE) {
        ssize_t r = otpe_tls_recv(tls, hb + got, OTPE_HEADER_SIZE - got);
        if (r <= 0) return -1;
        got += r;
    }
    if (!otpe_decode_header(hb, OTPE_HEADER_SIZE, h)) return -1;
    if (h->length > out_size) return -1;
    got = 0;
    while (got < h->length) {
        ssize_t r = otpe_tls_recv(tls, out + got, h->length - got);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}

static void* udp_listener_thread(void* arg) {
    (void)arg;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("udp socket"); return NULL; }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("udp bind");
        close(fd);
        return NULL;
    }
    socklen_t alen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &alen) < 0) {
        perror("udp getsockname");
        close(fd);
        return NULL;
    }
    g_udp_port = ntohs(addr.sin_port);
    printf("  UDP    on 127.0.0.1:%u\n", g_udp_port);

    struct sockaddr_storage cached_client;
    socklen_t cached_client_len = 0;
    otpe_tls_t* cached_tls = NULL;
    int cached_server_fd = -1;

    uint8_t buf[65536];
    uint8_t payload[65536];

    for (;;) {
        struct sockaddr_storage src;
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src, &src_len);
        if (n <= 0) continue;

        if (n < 10) continue;
        if (buf[0] != 0 || buf[1] != 0) continue;
        if (buf[2] != 0) continue;
        uint8_t atyp = buf[3];
        size_t pos = 4;
        char target_host[256];
        target_host[0] = '\0';
        uint16_t target_port = 0;

        if (atyp == 0x01) {
            if ((size_t)n < pos + 4 + 2) continue;
            snprintf(target_host, sizeof(target_host), "%u.%u.%u.%u",
                     buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]);
            pos += 4;
        } else if (atyp == 0x03) {
            if ((size_t)n < pos + 1) continue;
            uint8_t hl = buf[pos++];
            if ((size_t)n < pos + hl + 2) continue;
            memcpy(target_host, buf + pos, hl);
            target_host[hl] = '\0';
            pos += hl;
        } else if (atyp == 0x04) {
            if ((size_t)n < pos + 16 + 2) continue;
            snprintf(target_host, sizeof(target_host),
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     buf[pos], buf[pos+1], buf[pos+2], buf[pos+3],
                     buf[pos+4], buf[pos+5], buf[pos+6], buf[pos+7],
                     buf[pos+8], buf[pos+9], buf[pos+10], buf[pos+11],
                     buf[pos+12], buf[pos+13], buf[pos+14], buf[pos+15]);
            pos += 16;
        } else {
            continue;
        }

        if ((size_t)n < pos + 2) continue;
        target_port = (uint16_t)((buf[pos] << 8) | buf[pos+1]);
        pos += 2;

        const uint8_t* data = buf + pos;
        size_t data_len = (size_t)n - pos;

        if (data_len == 0) continue;
        if (data_len > 65000) continue;

        size_t hlen = strlen(target_host);
        if (hlen == 0 || hlen > 255) continue;

        size_t p = 0;
        payload[p++] = (uint8_t)hlen;
        memcpy(payload + p, target_host, hlen);
        p += hlen;
        payload[p++] = (uint8_t)((target_port >> 8) & 0xFF);
        payload[p++] = (uint8_t)(target_port & 0xFF);
        payload[p++] = (uint8_t)((data_len >> 8) & 0xFF);
        payload[p++] = (uint8_t)(data_len & 0xFF);
        memcpy(payload + p, data, data_len);
        p += data_len;

        int same = cached_tls
                && cached_client_len == src_len
                && memcmp(&cached_client, &src, src_len) == 0;

        if (!same) {
            if (cached_tls) { otpe_tls_free(cached_tls); close(cached_server_fd); }
            cached_tls = NULL;
            cached_server_fd = -1;
            cached_client_len = 0;

            int sfd = connect_server();
            if (sfd < 0) continue;

            otpe_tls_t* t = otpe_tls_client(sfd, g_cfg.sni);
            if (!t) { close(sfd); continue; }

            cached_tls = t;
            cached_server_fd = sfd;
            memcpy(&cached_client, &src, src_len);
            cached_client_len = src_len;
        }

        otpe_header_t h;
        h.version = OTPE_VERSION;
        h.command = OTPE_CMD_UDP;
        h.flags = 0;
        h.reserved = 0;
        h.length = (uint16_t)p;
        h.checksum = 0;
        memcpy(h.token, g_token, OTPE_TOKEN_SIZE);

        uint8_t frame[OTPE_HEADER_SIZE + 65540];
        otpe_encode_header(&h, frame, OTPE_HEADER_SIZE);
        memcpy(frame + OTPE_HEADER_SIZE, payload, p);

        if (otpe_tls_send(cached_tls, frame, OTPE_HEADER_SIZE + p) <= 0) {
            otpe_tls_free(cached_tls); close(cached_server_fd);
            cached_tls = NULL; cached_server_fd = -1; cached_client_len = 0;
            continue;
        }

        otpe_header_t rh;
        uint8_t rp[65540];
        ssize_t rn = udp_recv_tls_payload(cached_tls, &rh, rp, sizeof(rp));
        if (rn <= 0 || rh.command != OTPE_CMD_UDP) {
            otpe_tls_free(cached_tls); close(cached_server_fd);
            cached_tls = NULL; cached_server_fd = -1; cached_client_len = 0;
            continue;
        }

        size_t q = 0;
        if ((size_t)rn < 1) continue;
        uint8_t rhl = rp[q++];
        if (q + rhl + 4 > (size_t)rn) continue;
        char reply_host[256];
        memcpy(reply_host, rp + q, rhl);
        reply_host[rhl] = '\0';
        q += rhl;
        uint16_t reply_port = (uint16_t)((rp[q] << 8) | rp[q+1]);
        q += 2;
        uint16_t reply_dlen = (uint16_t)((rp[q] << 8) | rp[q+1]);
        q += 2;
        if (q + reply_dlen > (size_t)rn) continue;

        uint8_t socks_reply[65536];
        size_t sp = 0;
        socks_reply[sp++] = 0;
        socks_reply[sp++] = 0;
        socks_reply[sp++] = 0;

        struct in_addr a4;
        struct in6_addr a6;
        if (inet_pton(AF_INET, reply_host, &a4) == 1) {
            socks_reply[sp++] = 0x01;
            memcpy(socks_reply + sp, &a4, 4);
            sp += 4;
        } else if (inet_pton(AF_INET6, reply_host, &a6) == 1) {
            socks_reply[sp++] = 0x04;
            memcpy(socks_reply + sp, &a6, 16);
            sp += 16;
        } else {
            size_t hl = strlen(reply_host);
            if (hl > 255 || sp + 2 + hl + 2 + reply_dlen > sizeof(socks_reply)) continue;
            socks_reply[sp++] = 0x03;
            socks_reply[sp++] = (uint8_t)hl;
            memcpy(socks_reply + sp, reply_host, hl);
            sp += hl;
        }
        socks_reply[sp++] = (uint8_t)((reply_port >> 8) & 0xFF);
        socks_reply[sp++] = (uint8_t)(reply_port & 0xFF);
        memcpy(socks_reply + sp, rp + q, reply_dlen);
        sp += reply_dlen;

        sendto(fd, socks_reply, sp, 0, (struct sockaddr*)&src, src_len);
    }
    return NULL;
}

typedef struct {
    int listen_fd;
    void* (*handler)(void*);
} listener_t;

static void* listener_thread(void* arg) {
    listener_t* l = (listener_t*)arg;
    for (;;) {
        int fd = accept(l->listen_fd, NULL, NULL);
        if (fd < 0) continue;

        pthread_t t;
        if (pthread_create(&t, NULL, l->handler, (void*)(intptr_t)fd) != 0) {
            fprintf(stderr, "pthread_create failed (errno=%d)\n", errno);
            close(fd);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

int main(int argc, char** argv) {
    const char* cfg_path = argc > 1 ? argv[1] : "0tpe.conf";
    if (config_load_client(cfg_path, &g_cfg) != 0) {
        printf("Warning: config %s not found, using defaults\n", cfg_path);
    }
    config_token_to_bytes(g_cfg.token, g_token, OTPE_TOKEN_SIZE);

    if (crypto_load_public_key(g_cfg.reality_pubkey_file, &g_server_pubkey) != 0) {
        printf("Error: cannot load %s\n", g_cfg.reality_pubkey_file);
        return 1;
    }
    otpe_tls_set_server_pubkey(g_server_pubkey);

    signal(SIGPIPE, SIG_IGN);
    otpe_tls_init();

    int socks_fd = make_listen(g_cfg.socks_port);
    if (socks_fd < 0) { perror("bind socks"); return 1; }

    int http_fd = make_listen(g_cfg.http_port);
    if (http_fd < 0) { perror("bind http"); close(socks_fd); return 1; }

    printf("0TPE client -> %s:%u (SNI=%s)\n",
           g_cfg.server_ip, g_cfg.server_port, g_cfg.sni);
    printf("  SOCKS5 on 127.0.0.1:%u\n", g_cfg.socks_port);
    printf("  HTTP   on 127.0.0.1:%u\n", g_cfg.http_port);
    printf("  Reality pubkey: %s\n", g_cfg.reality_pubkey_file);

    pthread_t udp_tid;
    pthread_create(&udp_tid, NULL, udp_listener_thread, NULL);

    usleep(100000);

    static listener_t lt_socks, lt_http;
    lt_socks.listen_fd = socks_fd;
    lt_socks.handler = socks5_thread;
    lt_http.listen_fd = http_fd;
    lt_http.handler = http_thread;

    pthread_t t1, t2;
    pthread_create(&t1, NULL, listener_thread, &lt_socks);
    pthread_create(&t2, NULL, listener_thread, &lt_http);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(socks_fd);
    close(http_fd);
    return 0;
}