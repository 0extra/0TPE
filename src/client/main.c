#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "protocol.h"
#include "relay.h"
#include "tls.h"
#include "socks5.h"
#include "http_proxy.h"
#include "config.h"
#include "dns_cache.h"
#include "log.h"

#define UDP_IDLE_TIMEOUT 60
#define UDP_SESSIONS_HARD_MAX 256
#define TLS_MAX_RETRIES 3
#define TLS_RETRY_DELAY_MS 50

static otpe_client_config_t g_cfg;
static uint8_t g_token[OTPE_TOKEN_SIZE];
static X509* g_client_cert = NULL;
static EVP_PKEY* g_client_key = NULL;
static uint16_t g_udp_port = 0;
static int g_udp_socket = -1;
static volatile int g_shutdown = 0;
static int g_max_udp_sessions = 32;

static int connect_server(void) {
    int sock = otpe_connect_timeout(g_cfg.server_ip, g_cfg.server_port);
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

    ssize_t sent = otpe_tls_send_all(tls, buf, OTPE_HEADER_SIZE + payload_len);
    return sent == (ssize_t)(OTPE_HEADER_SIZE + payload_len) ? 0 : -1;
}

static otpe_tls_t* open_tls_with_retry(int* server_fd_out, const char* tag) {
    for (int attempt = 1; attempt <= TLS_MAX_RETRIES; attempt++) {
        int sfd = connect_server();
        if (sfd < 0) {
            if (attempt < TLS_MAX_RETRIES) usleep(TLS_RETRY_DELAY_MS * 1000);
            continue;
        }

        otpe_tls_t* tls = otpe_tls_client(sfd, g_cfg.sni, g_cfg.ca_file);
        if (tls) {
            *server_fd_out = sfd;
            return tls;
        }

        close(sfd);
        if (attempt < TLS_MAX_RETRIES) usleep(TLS_RETRY_DELAY_MS * 1000);
    }

    log_error("[%s] TLS handshake failed after %d attempts", tag, TLS_MAX_RETRIES);
    return NULL;
}

static void establish_tunnel(int browser_fd, const char* host, uint16_t port, const char* tag) {
    int server_fd = -1;
    otpe_tls_t* tls = open_tls_with_retry(&server_fd, tag);
    if (!tls) {
        close(browser_fd);
        return;
    }

    int connected = 0;
    for (int attempt = 1; attempt <= 2; attempt++) {
        if (send_connect_request(tls, host, port) == 0) {
            connected = 1;
            break;
        }
        log_warn("[%s] CONNECT failed (attempt %d) for %s:%u", tag, attempt, host, port);
        if (attempt < 2) usleep(TLS_RETRY_DELAY_MS * 1000);
    }

    if (!connected) {
        log_error("[%s] CONNECT failed permanently for %s:%u", tag, host, port);
        otpe_tls_free(tls);
        close(server_fd);
        close(browser_fd);
        return;
    }

    log_info("[%s] %s:%u", tag, host, port);

    long total = otpe_relay_tls_bidirectional(tls, browser_fd);

    if (total < 0) {
        log_warn("[%s] relay error for %s:%u", tag, host, port);
    } else {
        log_debug("[%s] closed %s:%u (%ld bytes)", tag, host, port, total);
    }

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
        establish_tunnel(fd, host, port, "SOCKS5");
    } else {
        log_info("[SOCKS5] UDP ASSOCIATE -> 127.0.0.1:%u", g_udp_port);
        uint8_t b;
        while (read(fd, &b, 1) > 0) {}
        close(fd);
    }
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
    establish_tunnel(fd, host, port, "HTTP");
    return NULL;
}

typedef struct {
    struct sockaddr_storage client;
    socklen_t client_len;
    otpe_tls_t* tls;
    int server_fd;
    int tls_fd;
    pthread_t tid;
    pthread_mutex_t lock;
    volatile int alive;
    volatile int in_use;
    time_t last_seen;
} udp_session_t;

static udp_session_t g_sessions[UDP_SESSIONS_HARD_MAX];
static pthread_mutex_t g_sessions_lock = PTHREAD_MUTEX_INITIALIZER;

static void udp_send_reply(udp_session_t* s, const uint8_t* payload, size_t len) {
    if (len < 5) return;
    size_t p = 0;
    uint8_t hlen = payload[p++];
    if (hlen == 0 || p + hlen + 4 > len) return;
    p += hlen;
    p += 2;
    uint16_t dlen = (uint16_t)((payload[p] << 8) | payload[p+1]);
    p += 2;
    if (p + dlen > len) return;

    uint8_t out[65540];
    size_t op = 0;
    out[op++] = 0; out[op++] = 0; out[op++] = 0; out[op++] = 0x01;
    out[op++] = 0; out[op++] = 0; out[op++] = 0; out[op++] = 0;
    out[op++] = 0; out[op++] = 0;
    if (op + dlen > sizeof(out)) return;
    memcpy(out + op, payload + p, dlen);
    op += dlen;
    sendto(g_udp_socket, out, op, 0, (struct sockaddr*)&s->client, s->client_len);
}

static void* udp_session_thread(void* arg) {
    udp_session_t* s = (udp_session_t*)arg;
    uint8_t hb[OTPE_HEADER_SIZE];
    uint8_t payload[65540];

    while (s->alive && !g_shutdown) {
        time_t now = time(NULL);
        if (now - s->last_seen > UDP_IDLE_TIMEOUT) break;

        if (otpe_tls_pending(s->tls) <= 0) {
            struct pollfd pfd;
            pfd.fd = s->tls_fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int r = poll(&pfd, 1, 1000);
            if (r < 0) { if (errno == EINTR) continue; break; }
            if (r == 0) continue;
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) continue;
        }

        pthread_mutex_lock(&s->lock);
        ssize_t hn = otpe_tls_recv_all(s->tls, hb, OTPE_HEADER_SIZE);
        if (hn != OTPE_HEADER_SIZE) { pthread_mutex_unlock(&s->lock); break; }
        otpe_header_t h;
        if (!otpe_decode_header(hb, OTPE_HEADER_SIZE, &h) || h.command != OTPE_CMD_UDP) {
            pthread_mutex_unlock(&s->lock);
            break;
        }
        ssize_t pn = otpe_tls_recv_all(s->tls, payload, h.length);
        pthread_mutex_unlock(&s->lock);
        if (pn != (ssize_t)h.length) break;

        udp_send_reply(s, payload, (size_t)pn);
        s->last_seen = now;
    }
    s->alive = 0;
    return NULL;
}

static udp_session_t* udp_find_or_create(struct sockaddr_storage* src, socklen_t src_len) {
    time_t now = time(NULL);
    for (int i = 0; i < g_max_udp_sessions; i++) {
        udp_session_t* s = &g_sessions[i];
        if (s->in_use && s->alive && s->client_len == src_len &&
            memcmp(&s->client, src, src_len) == 0) return s;
    }
    int slot = -1;
    for (int i = 0; i < g_max_udp_sessions; i++) if (!g_sessions[i].in_use) { slot = i; break; }
    if (slot < 0) for (int i = 0; i < g_max_udp_sessions; i++) if (!g_sessions[i].alive) { slot = i; break; }
    if (slot < 0) return NULL;

    udp_session_t* s = &g_sessions[slot];
    if (s->in_use) {
        s->alive = 0;
        pthread_join(s->tid, NULL);
        if (s->tls) otpe_tls_free(s->tls);
        if (s->server_fd >= 0) close(s->server_fd);
    } else {
        pthread_mutex_init(&s->lock, NULL);
    }

    memset(&s->client, 0, sizeof(s->client));
    memcpy(&s->client, src, src_len);
    s->client_len = src_len;
    s->last_seen = now;
    s->in_use = 1;
    s->alive = 0;
    s->tls = NULL;
    s->server_fd = -1;
    s->tls_fd = -1;

    int sfd = -1;
    otpe_tls_t* t = open_tls_with_retry(&sfd, "UDP");
    if (!t) {
        s->in_use = 0;
        return NULL;
    }

    s->tls = t;
    s->server_fd = sfd;
    s->tls_fd = otpe_tls_get_fd(t);
    s->alive = 1;

    if (pthread_create(&s->tid, NULL, udp_session_thread, s) != 0) {
        log_error("udp: pthread_create failed");
        s->alive = 0;
        s->in_use = 0;
        otpe_tls_free(s->tls);
        close(s->server_fd);
        s->tls = NULL;
        s->server_fd = -1;
        return NULL;
    }
    return s;
}

static void* udp_listener_thread(void* arg) {
    (void)arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return NULL; }
    socklen_t alen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &alen) < 0) { close(fd); return NULL; }
    g_udp_port = ntohs(addr.sin_port);
    g_udp_socket = fd;
    log_info("  UDP    on 127.0.0.1:%u", g_udp_port);

    uint8_t buf[65540];
    while (!g_shutdown) {
        struct sockaddr_storage src;
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src, &src_len);
        if (n <= 0) continue;
        if (n < 10) continue;
        if (buf[0] != 0 || buf[1] != 0 || buf[2] != 0) continue;
        uint8_t atyp = buf[3];
        size_t pos = 4;
        char host[256];
        host[0] = '\0';
        uint16_t port = 0;
        if (atyp == 0x01) {
            if ((size_t)n < pos + 6) continue;
            snprintf(host, sizeof(host), "%u.%u.%u.%u", buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]);
            pos += 4;
        } else if (atyp == 0x03) {
            if ((size_t)n < pos + 1) continue;
            uint8_t hl = buf[pos++];
            if (hl == 0 || (size_t)n < pos + hl + 2) continue;
            memcpy(host, buf + pos, hl);
            host[hl] = '\0';
            pos += hl;
        } else if (atyp == 0x04) {
            if ((size_t)n < pos + 18) continue;
            snprintf(host, sizeof(host),
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                buf[pos], buf[pos+1], buf[pos+2], buf[pos+3], buf[pos+4], buf[pos+5], buf[pos+6], buf[pos+7],
                buf[pos+8], buf[pos+9], buf[pos+10], buf[pos+11], buf[pos+12], buf[pos+13], buf[pos+14], buf[pos+15]);
            pos += 16;
        } else continue;

        if ((size_t)n < pos + 2) continue;
        port = (uint16_t)((buf[pos] << 8) | buf[pos+1]);
        pos += 2;
        const uint8_t* data = buf + pos;
        size_t data_len = (size_t)n - pos;
        if (data_len == 0 || data_len > 65000) continue;
        size_t hlen = strlen(host);
        if (hlen == 0 || hlen > 255) continue;

        uint8_t payload[65540];
        size_t p = 0;
        payload[p++] = (uint8_t)hlen;
        memcpy(payload + p, host, hlen); p += hlen;
        payload[p++] = (uint8_t)((port >> 8) & 0xFF);
        payload[p++] = (uint8_t)(port & 0xFF);
        payload[p++] = (uint8_t)((data_len >> 8) & 0xFF);
        payload[p++] = (uint8_t)(data_len & 0xFF);
        memcpy(payload + p, data, data_len); p += data_len;

        pthread_mutex_lock(&g_sessions_lock);
        udp_session_t* s = udp_find_or_create(&src, src_len);
        if (!s) { pthread_mutex_unlock(&g_sessions_lock); continue; }

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
        pthread_mutex_lock(&s->lock);
        otpe_tls_send_all(s->tls, frame, OTPE_HEADER_SIZE + p);
        pthread_mutex_unlock(&s->lock);
        s->last_seen = time(NULL);
        pthread_mutex_unlock(&g_sessions_lock);
    }
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
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, 128) < 0) { close(fd); return -1; }
    return fd;
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
        return 1;
    }
    if (config_validate_client(&g_cfg) != 0) {
        return 1;
    }

    int lvl = log_level_from_string(g_cfg.log_level);
    if (lvl < 0) {
        fprintf(stderr, "config: invalid log_level '%s'\n", g_cfg.log_level);
        return 1;
    }
    log_set_level((log_level_t)lvl);

    g_max_udp_sessions = (int)g_cfg.max_udp_sessions;

    config_token_to_bytes(g_cfg.token, g_token, OTPE_TOKEN_SIZE);

    FILE* certf = fopen(g_cfg.client_cert_file, "r");
    if (!certf) {
        log_error("cannot open %s", g_cfg.client_cert_file);
        return 1;
    }
    g_client_cert = PEM_read_X509(certf, NULL, NULL, NULL);
    fclose(certf);
    if (!g_client_cert) {
        log_error("invalid client certificate");
        return 1;
    }

    FILE* keyf = fopen(g_cfg.client_key_file, "r");
    if (!keyf) {
        log_error("cannot open %s", g_cfg.client_key_file);
        return 1;
    }
    g_client_key = PEM_read_PrivateKey(keyf, NULL, NULL, NULL);
    fclose(keyf);
    if (!g_client_key) {
        log_error("invalid client key");
        return 1;
    }

    otpe_tls_set_client_cert(g_client_cert, g_client_key);

    signal(SIGPIPE, SIG_IGN);
    otpe_tls_init();
    dns_cache_init();

    int socks_fd = make_listen(g_cfg.socks_port);
    if (socks_fd < 0) { perror("bind socks"); return 1; }
    int http_fd = make_listen(g_cfg.http_port);
    if (http_fd < 0) { perror("bind http"); close(socks_fd); return 1; }

    log_info("0TPE client -> %s:%u (SNI=%s)",
             g_cfg.server_ip, g_cfg.server_port, g_cfg.sni);
    log_info("  SOCKS5 on 127.0.0.1:%u", g_cfg.socks_port);
    log_info("  HTTP   on 127.0.0.1:%u", g_cfg.http_port);
    log_info("  CA file: %s", g_cfg.ca_file);
    log_info("  Client cert: %s", g_cfg.client_cert_file);
    log_info("  TLS retries: %d", TLS_MAX_RETRIES);
    log_info("  Max UDP sessions: %d", g_max_udp_sessions);
    log_info("  Log level: %s", log_level_to_string(log_get_level()));

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