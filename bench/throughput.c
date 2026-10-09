#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "protocol.h"
#include "relay.h"
#include "tls.h"
#include "config.h"
#include "dns_cache.h"

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char** argv) {
    const char* cfg_path = argc > 1 ? argv[1] : "0tpe.conf";
    long total_mb = argc > 2 ? atol(argv[2]) : 100;

    otpe_client_config_t cfg;
    if (config_load_client(cfg_path, &cfg) != 0) {
        fprintf(stderr, "cannot load %s\n", cfg_path);
        return 1;
    }

    X509* cert = NULL;
    EVP_PKEY* key = NULL;

    FILE* cf = fopen(cfg.client_cert_file, "r");
    if (cf) { cert = PEM_read_X509(cf, NULL, NULL, NULL); fclose(cf); }
    FILE* kf = fopen(cfg.client_key_file, "r");
    if (kf) { key = PEM_read_PrivateKey(kf, NULL, NULL, NULL); fclose(kf); }
    if (!cert || !key) {
        fprintf(stderr, "cannot load client cert/key\n");
        return 1;
    }
    otpe_tls_set_client_cert(cert, key);
    otpe_tls_init();
    dns_cache_init();

    uint8_t token[OTPE_TOKEN_SIZE];
    config_token_to_bytes(cfg.token, token, OTPE_TOKEN_SIZE);

    int sock = otpe_connect_timeout(cfg.server_ip, cfg.server_port);
    if (sock < 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }
    otpe_set_tcp_nodelay(sock);

    otpe_tls_t* tls = otpe_tls_client(sock, cfg.sni, cfg.ca_file);
    if (!tls) {
        fprintf(stderr, "TLS handshake failed\n");
        close(sock);
        return 1;
    }

    const char* host = "cachefly.cachefly.net";
    uint16_t port = 80;
    const char* path = "/100mb.test";

    otpe_header_t h;
    h.version = OTPE_VERSION;
    h.command = OTPE_CMD_CONNECT;
    h.flags = 0;
    h.reserved = 0;
    h.length = (uint16_t)(2 + strlen(host));
    h.checksum = 0;
    memcpy(h.token, token, OTPE_TOKEN_SIZE);

    uint8_t req[OTPE_HEADER_SIZE + 128];
    otpe_encode_header(&h, req, OTPE_HEADER_SIZE);
    req[OTPE_HEADER_SIZE]     = (uint8_t)((port >> 8) & 0xFF);
    req[OTPE_HEADER_SIZE + 1] = (uint8_t)(port & 0xFF);
    memcpy(req + OTPE_HEADER_SIZE + 2, host, strlen(host));

    if (otpe_tls_send(tls, req, OTPE_HEADER_SIZE + 2 + strlen(host)) <= 0) {
        fprintf(stderr, "CONNECT failed\n");
        return 1;
    }

    char http_req[512];
    snprintf(http_req, sizeof(http_req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: curl/8.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n", path, host);

    if (otpe_tls_send(tls, http_req, strlen(http_req)) <= 0) {
        fprintf(stderr, "request failed\n");
        return 1;
    }

    printf("Downloading %s from %s:%u (target %ld MB) ...\n", path, host, port, total_mb);

    static uint8_t buf[65536];
    long long total = 0;
    uint64_t t0 = now_ns();
    uint64_t last = t0;
    int header_done = 0;
    long long header_bytes = 0;
    long long target_bytes = (long long)total_mb * 1024 * 1024;

    for (;;) {
        ssize_t n = otpe_tls_recv(tls, buf, sizeof(buf));
        if (n <= 0) break;
        total += n;

        if (!header_done) {
            for (ssize_t i = 0; i <= n - 4; i++) {
                if (buf[i] == '\r' && buf[i+1] == '\n' &&
                    buf[i+2] == '\r' && buf[i+3] == '\n') {
                    header_done = 1;
                    header_bytes = total - (n - (i + 4));
                    char hdr[200];
                    ssize_t cp = (i + 1 < 200) ? (i + 1) : 199;
                    memcpy(hdr, buf, (size_t)cp);
                    hdr[cp] = '\0';
                    char* nl = strchr(hdr, '\r');
                    if (nl) *nl = '\0';
                    printf("HTTP: %s\n", hdr);
                    break;
                }
            }
        }

        uint64_t now = now_ns();
        if (now - last >= 1000000000ULL) {
            double sec = (double)(now - t0) / 1e9;
            double mb = (double)(total - header_bytes) / (1024.0 * 1024.0);
            if (sec > 0.1 && mb > 0)
                printf("\r%.2f MB in %.1fs (%.2f MB/s)", mb, sec, mb / sec);
            fflush(stdout);
            last = now;
        }

        if (total - header_bytes >= target_bytes) break;
    }

    double sec = (double)(now_ns() - t0) / 1e9;
    double mb = (double)(total - header_bytes) / (1024.0 * 1024.0);
    double mbps = mb * 8.0 / sec;

    printf("\n\n=== 0TPE throughput benchmark ===\n");
    printf("raw bytes:   %lld\n", total);
    printf("payload:     %lld\n", total - header_bytes);
    printf("elapsed:     %.3f s\n", sec);
    printf("throughput:  %.2f MB/s (%.2f Mbps)\n", mb / sec, mbps);

    otpe_tls_free(tls);
    close(sock);
    return 0;
}