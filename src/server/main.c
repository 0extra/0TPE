#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include "protocol.h"
#include "relay.h"
#include "tls.h"
#include "tls_peek.h"
#include "config.h"
#include "dns_cache.h"
#include "udp_stateful.h"
#include "log.h"

static otpe_server_config_t g_cfg;
static int g_active_connections = 0;
static pthread_mutex_t g_conn_lock = PTHREAD_MUTEX_INITIALIZER;

static int connect_target(const char* host, uint16_t port) {
    return otpe_connect_timeout(host, port);
}

static void handle_fallback(int client, const char* sni) {
    const char* target_host = (sni && *sni) ? sni : g_cfg.fallback_sni;
    log_info("[fallback] -> %s:443", target_host);
    int remote = connect_target(target_host, 443);
    if (remote < 0) {
        log_warn("[fallback] cannot connect to %s:443", target_host);
        close(client);
        return;
    }
    otpe_set_tcp_nodelay(remote);
    otpe_relay_bidirectional(client, remote);
    close(remote);
    close(client);
}

static void process_udp_payload(udp_target_t* targets,
                                const uint8_t* payload, size_t len) {
    if (len < 1) return;

    size_t p = 0;
    uint8_t hlen = payload[p++];
    if (hlen == 0 || p + hlen + 4 > len) return;

    char host[256];
    memcpy(host, payload + p, hlen);
    host[hlen] = '\0';
    p += hlen;

    uint16_t port = (uint16_t)((payload[p] << 8) | payload[p + 1]);
    p += 2;

    uint16_t dlen = (uint16_t)((payload[p] << 8) | payload[p + 1]);
    p += 2;

    if (p + dlen > len) return;

    int idx = udp_state_get_or_create(targets, host, port);
    if (idx < 0) {
        log_warn("[udp] cannot reach %s:%u", host, port);
        return;
    }

    send(targets[idx].fd, payload + p, dlen, 0);
    targets[idx].last_seen = time(NULL);
}

static int flush_udp_replies(otpe_tls_t* tls, udp_target_t* targets,
                             const uint8_t* token) {
    uint8_t reply[65540];
    size_t reply_len = 0;
    char reply_host[256];
    uint16_t reply_port = 0;

    while (udp_state_poll(targets, reply, sizeof(reply), &reply_len,
                          reply_host, sizeof(reply_host), &reply_port) == 1) {
        if (reply_len > 65535) continue;

        otpe_header_t rh;
        rh.version  = OTPE_VERSION;
        rh.command  = OTPE_CMD_UDP;
        rh.flags    = 0;
        rh.reserved = 0;
        rh.length   = (uint16_t)reply_len;
        rh.checksum = 0;
        memcpy(rh.token, token, OTPE_TOKEN_SIZE);

        uint8_t out[OTPE_HEADER_SIZE + 65540];
        otpe_encode_header(&rh, out, OTPE_HEADER_SIZE);
        memcpy(out + OTPE_HEADER_SIZE, reply, reply_len);

        if (otpe_tls_send_all(tls, out, OTPE_HEADER_SIZE + reply_len) <= 0) {
            return -1;
        }
    }
    return 0;
}

static void handle_udp_session(otpe_tls_t* tls, const uint8_t* token,
                               const uint8_t* initial_payload, size_t initial_len) {
    udp_target_t targets[UDP_TARGETS_MAX];
    udp_state_init(targets);

    uint8_t hb[OTPE_HEADER_SIZE];
    uint8_t payload[65540];
    int tls_fd = otpe_tls_get_fd(tls);

    process_udp_payload(targets, initial_payload, initial_len);

    if (flush_udp_replies(tls, targets, token) < 0) {
        udp_state_cleanup(targets);
        return;
    }

    for (;;) {
        int tls_ready = otpe_tls_pending(tls) > 0;
        if (!tls_ready) {
            struct pollfd pfd = { .fd = tls_fd, .events = POLLIN };
            if (poll(&pfd, 1, 30) > 0 && (pfd.revents & POLLIN)) {
                tls_ready = 1;
            }
        }

        if (tls_ready) {
            if (otpe_tls_recv_all(tls, hb, OTPE_HEADER_SIZE) != OTPE_HEADER_SIZE) break;

            otpe_header_t h;
            if (!otpe_decode_header(hb, OTPE_HEADER_SIZE, &h)) break;
            if (h.command != OTPE_CMD_UDP) break;
            if (h.length < 1) break;

            if (otpe_tls_recv_all(tls, payload, h.length) != h.length) break;

            process_udp_payload(targets, payload, h.length);
        }

        if (flush_udp_replies(tls, targets, token) < 0) break;
    }

    udp_state_cleanup(targets);
}

static void handle_client(int client) {
    char sni[256];
    int has_otpe_alpn = 0;

    if (tls_peek_clienthello(client, sni, sizeof(sni), &has_otpe_alpn) < 0) {
        handle_fallback(client, NULL);
        return;
    }

    if (!has_otpe_alpn) {
        handle_fallback(client, sni);
        return;
    }

    log_info("[tid %lu] 0TPE client, SNI=%s",
             (unsigned long)pthread_self(), sni);

    otpe_tls_t* tls = otpe_tls_server(client, g_cfg.cert_file, g_cfg.key_file, g_cfg.ca_file);
    if (!tls) {
        log_warn("[tid %lu] TLS failed (client cert rejected?)",
                 (unsigned long)pthread_self());
        return;
    }
    log_debug("[tid %lu] TLS OK", (unsigned long)pthread_self());

    uint8_t hb[OTPE_HEADER_SIZE];
    if (otpe_tls_recv_all(tls, hb, OTPE_HEADER_SIZE) != OTPE_HEADER_SIZE) {
        otpe_tls_free(tls);
        return;
    }
    otpe_header_t h;
    if (!otpe_decode_header(hb, OTPE_HEADER_SIZE, &h) || !otpe_validate_header(&h)) {
        otpe_tls_free(tls);
        return;
    }

    if (h.command == OTPE_CMD_PING) {
        otpe_header_t reply = h;
        reply.command  = OTPE_CMD_PONG;
        reply.length   = 0;
        reply.checksum = 0;
        uint8_t out[OTPE_HEADER_SIZE];
        otpe_encode_header(&reply, out, sizeof(out));
        otpe_tls_send_all(tls, out, OTPE_HEADER_SIZE);

        uint8_t payload[65536];
        for (;;) {
            if (otpe_tls_recv_all(tls, hb, OTPE_HEADER_SIZE) != OTPE_HEADER_SIZE) break;
            if (!otpe_decode_header(hb, OTPE_HEADER_SIZE, &h)) break;
            if (!otpe_validate_header(&h)) break;
            if (h.command != OTPE_CMD_PING) break;
            if (h.length > 0) {
                if (otpe_tls_recv_all(tls, payload, h.length) != h.length) break;
            }
            otpe_tls_send_all(tls, out, OTPE_HEADER_SIZE);
        }
        otpe_tls_free(tls);
        return;
    }

    if (h.command == OTPE_CMD_CONNECT) {
        if (h.length < 2 || h.length > 258) {
            otpe_tls_free(tls);
            return;
        }

        uint8_t payload[258];
        if (otpe_tls_recv_all(tls, payload, h.length) != h.length) {
            otpe_tls_free(tls);
            return;
        }

        uint16_t port = (uint16_t)((payload[0] << 8) | payload[1]);
        if (port == 0) {
            otpe_tls_free(tls);
            return;
        }

        char host[256];
        size_t hlen = h.length - 2;
        if (hlen == 0 || hlen >= sizeof(host)) {
            otpe_tls_free(tls);
            return;
        }
        memcpy(host, payload + 2, hlen);
        host[hlen] = '\0';

        log_info("[tid %lu] CONNECT %s:%u",
                 (unsigned long)pthread_self(), host, port);
        int target = connect_target(host, port);
        if (target < 0) {
            log_warn("[tid %lu] cannot connect %s:%u",
                     (unsigned long)pthread_self(), host, port);
            otpe_tls_free(tls);
            return;
        }
        otpe_set_tcp_nodelay(target);
        log_debug("[tid %lu] up %s:%u",
                  (unsigned long)pthread_self(), host, port);
        otpe_relay_tls_bidirectional(tls, target);
        close(target);
        log_debug("[tid %lu] closed", (unsigned long)pthread_self());
        otpe_tls_free(tls);
        return;
    }

    if (h.command == OTPE_CMD_UDP) {
        if (h.length < 1) {
            otpe_tls_free(tls);
            return;
        }
        uint8_t payload[65540];
        if (otpe_tls_recv_all(tls, payload, h.length) != h.length) {
            otpe_tls_free(tls);
            return;
        }
        handle_udp_session(tls, h.token, payload, h.length);
        otpe_tls_free(tls);
        return;
    }

    otpe_tls_free(tls);
}

static void* thread_entry(void* arg) {
    int client = (int)(intptr_t)arg;
    otpe_set_tcp_nodelay(client);
    handle_client(client);
    close(client);
    pthread_mutex_lock(&g_conn_lock);
    g_active_connections--;
    pthread_mutex_unlock(&g_conn_lock);
    return NULL;
}

int main(int argc, char** argv) {
    const char* cfg_path = argc > 1 ? argv[1] : "0tpe.conf";
    if (config_load_server(cfg_path, &g_cfg) != 0) {
        return 1;
    }
    if (config_validate_server(&g_cfg) != 0) {
        return 1;
    }

    int lvl = log_level_from_string(g_cfg.log_level);
    if (lvl < 0) {
        fprintf(stderr, "config: invalid log_level '%s'\n", g_cfg.log_level);
        return 1;
    }
    log_set_level((log_level_t)lvl);

    signal(SIGPIPE, SIG_IGN);
    otpe_tls_init();
    otpe_tls_server_preinit(g_cfg.cert_file, g_cfg.key_file, g_cfg.ca_file);
    dns_cache_init();

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

    log_info("0TPE server listening on %s:%u", g_cfg.listen_ip, g_cfg.listen_port);
    log_info("Fallback SNI: %s", g_cfg.fallback_sni);
    log_info("Client cert required (CA: %s)", g_cfg.ca_file);
    log_info("Max connections: %u", g_cfg.max_connections);
    log_info("Log level: %s", log_level_to_string(log_get_level()));

    for (;;) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int client = accept(server_sock, (struct sockaddr*)&caddr, &clen);
        if (client < 0) continue;

        pthread_mutex_lock(&g_conn_lock);
        if (g_active_connections >= (int)g_cfg.max_connections) {
            pthread_mutex_unlock(&g_conn_lock);
            log_warn("connection limit reached (%u), rejecting", g_cfg.max_connections);
            close(client);
            continue;
        }
        g_active_connections++;
        pthread_mutex_unlock(&g_conn_lock);

        pthread_t t;
        if (pthread_create(&t, NULL, thread_entry, (void*)(intptr_t)client) != 0) {
            pthread_mutex_lock(&g_conn_lock);
            g_active_connections--;
            pthread_mutex_unlock(&g_conn_lock);
            close(client);
            continue;
        }
        pthread_detach(t);
    }
    close(server_sock);
    return 0;
}