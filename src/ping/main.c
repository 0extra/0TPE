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

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

int main(int argc, char** argv) {
    otpe_client_config_t cfg;
    if (config_load_client("0tpe.conf", &cfg) != 0) {
        fprintf(stderr, "cannot load 0tpe.conf\n");
        return 1;
    }
    if (config_validate_client(&cfg) != 0) {
        return 1;
    }

    if (argc > 1) {
        strncpy(cfg.server_ip, argv[1], sizeof(cfg.server_ip) - 1);
        cfg.server_ip[sizeof(cfg.server_ip) - 1] = '\0';
    }
    if (argc > 2) cfg.server_port = (uint16_t)atoi(argv[2]);
    int count = argc > 3 ? atoi(argv[3]) : 10;

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

    printf("PING 0TPE %s:%u\n", cfg.server_ip, cfg.server_port);

    double sum = 0.0;
    int ok = 0;

    for (int i = 0; i < count; i++) {
        otpe_header_t req;
        req.version = OTPE_VERSION;
        req.command = OTPE_CMD_PING;
        req.flags = 0;
        req.reserved = 0;
        req.length = 0;
        req.checksum = 0;
        memcpy(req.token, token, OTPE_TOKEN_SIZE);

        uint8_t out[OTPE_HEADER_SIZE];
        otpe_encode_header(&req, out, sizeof(out));

        double t0 = now_ms();
        if (otpe_tls_send(tls, out, OTPE_HEADER_SIZE) <= 0) break;

        uint8_t in[OTPE_HEADER_SIZE];
        ssize_t n = otpe_tls_recv(tls, in, OTPE_HEADER_SIZE);
        double t1 = now_ms();

        if (n != OTPE_HEADER_SIZE) {
            printf("timeout seq=%d\n", i);
            continue;
        }

        otpe_header_t rep;
        if (!otpe_decode_header(in, n, &rep) || rep.command != OTPE_CMD_PONG) {
            printf("bad reply seq=%d\n", i);
            continue;
        }

        double rtt = t1 - t0;
        printf("reply from %s: seq=%d time=%.2f ms\n", cfg.server_ip, i, rtt);
        sum += rtt;
        ok++;
    }

    printf("--- %s 0TPE ping statistics ---\n", cfg.server_ip);
    printf("%d packets transmitted, %d received\n", count, ok);
    if (ok > 0) printf("rtt avg = %.2f ms\n", sum / ok);

    otpe_tls_free(tls);
    close(sock);
    return 0;
}