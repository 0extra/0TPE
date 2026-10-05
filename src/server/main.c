#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include "protocol.h"
#include "relay.h"
#include "tls.h"
#include "tls_peek.h"
#include "crypto.h"
#include "config.h"
#include "nonce_cache.h"

static otpe_server_config_t g_cfg;
static void* g_server_privkey = NULL;

static int connect_target(const char* host, uint16_t port) {
    return otpe_connect_timeout(host, port, 5000);
}

static void handle_fallback(int client, const char* sni) {
    const char* target_host = (sni && *sni) ? sni : g_cfg.fallback_sni;
    printf("[fallback] -> %s:443\n", target_host);

    int remote = connect_target(target_host, 443);
    if (remote < 0) {
        printf("[fallback] cannot connect to %s:443\n", target_host);
        close(client);
        return;
    }
    otpe_set_tcp_nodelay(remote);
    otpe_relay_bidirectional(client, remote);
    close(remote);
    close(client);
}

static void handle_udp_frame(otpe_tls_t* tls, const uint8_t* token,
                             const uint8_t* payload, size_t payload_len) {
    if (payload_len < 1) return;
    size_t p = 0;
    uint8_t hlen = payload[p++];
    if (hlen == 0) return;
    if (p + hlen + 4 > payload_len) return;

    char host[256];
    memcpy(host, payload + p, hlen);
    host[hlen] = '\0';
    p += hlen;

    uint16_t port = (uint16_t)((payload[p] << 8) | payload[p+1]);
    p += 2;
    uint16_t data_len = (uint16_t)((payload[p] << 8) | payload[p+1]);
    p += 2;
    if (p + data_len > payload_len) return;

    const uint8_t* data = payload + p;

    printf("[UDP tid %lu] -> %s:%u (%u bytes)\n",
           (unsigned long)pthread_self(), host, port, data_len);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo* res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return;

    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return;

    if (send(fd, data, data_len, 0) != (ssize_t)data_len) {
        close(fd);
        return;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ready = poll(&pfd, 1, 5000);
    if (ready > 0) {
        uint8_t reply[65536];
        ssize_t rn = recv(fd, reply, sizeof(reply), 0);
        if (rn > 0) {
            size_t rhlen = strlen(host);
            size_t total = 1 + rhlen + 2 + 2 + (size_t)rn;
            if (total <= 65535) {
                uint8_t out[OTPE_HEADER_SIZE + 65540];
                otpe_header_t h;
                h.version = OTPE_VERSION;
                h.command = OTPE_CMD_UDP;
                h.flags = 0;
                h.reserved = 0;
                h.length = (uint16_t)total;
                h.checksum = 0;
                memcpy(h.token, token, OTPE_TOKEN_SIZE);

                otpe_encode_header(&h, out, OTPE_HEADER_SIZE);
                size_t op = OTPE_HEADER_SIZE;
                out[op++] = (uint8_t)rhlen;
                memcpy(out + op, host, rhlen);
                op += rhlen;
                out[op++] = (uint8_t)((port >> 8) & 0xFF);
                out[op++] = (uint8_t)(port & 0xFF);
                out[op++] = (uint8_t)(((size_t)rn >> 8) & 0xFF);
                out[op++] = (uint8_t)((size_t)rn & 0xFF);
                memcpy(out + op, reply, (size_t)rn);
                op += (size_t)rn;

                otpe_tls_send_all(tls, out, op);
            }
        }
    }
    close(fd);
}

static void handle_client(int client) {
    char sni[256];
    uint8_t ext_data[256];
    size_t ext_len = 0;

    if (tls_peek_clienthello(client, sni, sizeof(sni), ext_data, sizeof(ext_data), &ext_len) < 0) {
        handle_fallback(client, NULL);
        return;
    }

    int is_ours = 0;
    int verify_result = -1;
    if (g_server_privkey && ext_len >= OTPE_EXT_DATA_SIZE) {
        verify_result = crypto_verify_extension(g_server_privkey, ext_data, ext_len);
        if (verify_result == 0) {
            is_ours = 1;
        }
    }

    if (!is_ours) {
        printf("[fallback] verify_result=%d ext_len=%zu\n", verify_result, ext_len);
        handle_fallback(client, sni);
        return;
    }

    printf("[tid %lu] OTPE client, SNI=%s\n", (unsigned long)pthread_self(), sni);

    otpe_tls_t* tls = otpe_tls_server(client, g_cfg.cert_file, g_cfg.key_file);
    if (!tls) {
        printf("[tid %lu] TLS failed\n", (unsigned long)pthread_self());
        return;
    }
    printf("[tid %lu] TLS OK\n", (unsigned long)pthread_self());

    uint8_t payload[65540];

    for (;;) {
        uint8_t header_buf[OTPE_HEADER_SIZE];
        ssize_t hn = otpe_tls_recv(tls, header_buf, OTPE_HEADER_SIZE);
        if (hn != OTPE_HEADER_SIZE) break;

        otpe_header_t header;
        if (!otpe_decode_header(header_buf, hn, &header)) break;
        if (!otpe_validate_header(&header)) break;

        if (header.command == OTPE_CMD_PING) {
            otpe_header_t reply = header;
            reply.command = OTPE_CMD_PONG;
            reply.length = 0;
            reply.checksum = 0;
            uint8_t out[OTPE_HEADER_SIZE];
            otpe_encode_header(&reply, out, sizeof(out));
            if (otpe_tls_send_all(tls, out, OTPE_HEADER_SIZE) <= 0) break;
            continue;
        }

        if (header.command == OTPE_CMD_UDP) {
            ssize_t pn = 0;
            while (pn < header.length) {
                ssize_t r = otpe_tls_recv(tls, payload + pn, (size_t)(header.length - pn));
                if (r <= 0) { otpe_tls_free(tls); return; }
                pn += r;
            }
            handle_udp_frame(tls, header.token, payload, (size_t)pn);
            continue;
        }

        if (header.command == OTPE_CMD_CONNECT) {
            ssize_t pn = 0;
            while (pn < header.length) {
                ssize_t r = otpe_tls_recv(tls, payload + pn, (size_t)(header.length - pn));
                if (r <= 0) { otpe_tls_free(tls); return; }
                pn += r;
            }

            uint16_t port = (uint16_t)((payload[0] << 8) | payload[1]);
            char host[256];
            size_t host_len = header.length - 2;
            if (host_len >= sizeof(host)) break;
            memcpy(host, payload + 2, host_len);
            host[host_len] = '\0';

            printf("[tid %lu] CONNECT %s:%u\n", (unsigned long)pthread_self(), host, port);

            int target = connect_target(host, port);
            if (target < 0) {
                printf("[tid %lu] failed %s:%u\n", (unsigned long)pthread_self(), host, port);
                break;
            }
            otpe_set_tcp_nodelay(target);
            printf("[tid %lu] up %s:%u\n", (unsigned long)pthread_self(), host, port);

            otpe_relay_tls_bidirectional(tls, target);

            printf("[tid %lu] closed\n", (unsigned long)pthread_self());
            close(target);
            break;
        }

        break;
    }

    otpe_tls_free(tls);
}

static void* thread_entry(void* arg) {
    int client = (int)(intptr_t)arg;
    otpe_set_tcp_nodelay(client);
    handle_client(client);
    close(client);
    return NULL;
}

int main(int argc, char** argv) {
    const char* cfg_path = argc > 1 ? argv[1] : "0tpe.conf";
    if (config_load_server(cfg_path, &g_cfg) != 0) {
        printf("Warning: config %s not found, using defaults\n", cfg_path);
    }

    signal(SIGPIPE, SIG_IGN);
    otpe_tls_init();
    nonce_cache_init();

    if (crypto_load_private_key(g_cfg.reality_key_file, &g_server_privkey) != 0) {
        printf("Warning: cannot load reality key %s — fallback for everyone\n", g_cfg.reality_key_file);
    } else {
        printf("Reality private key loaded: %s\n", g_cfg.reality_key_file);
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) return 1;

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(g_cfg.listen_ip);
    addr.sin_port = htons(g_cfg.listen_port);

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_sock);
        return 1;
    }
    if (listen(server_sock, 128) < 0) {
        perror("listen");
        close(server_sock);
        return 1;
    }

    printf("0TPE+TLS server listening on %s:%u\n", g_cfg.listen_ip, g_cfg.listen_port);
    printf("Fallback SNI: %s\n", g_cfg.fallback_sni);

    for (;;) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int client = accept(server_sock, (struct sockaddr*)&caddr, &clen);
        if (client < 0) continue;

        pthread_t t;
        if (pthread_create(&t, NULL, thread_entry, (void*)(intptr_t)client) != 0) {
            fprintf(stderr, "pthread_create failed (errno=%d)\n", errno);
            close(client);
            continue;
        }
        pthread_detach(t);
    }

    close(server_sock);
    return 0;
}