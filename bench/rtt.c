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

static int compare_u64(const void* a, const void* b) {
    uint64_t ua = *(const uint64_t*)a;
    uint64_t ub = *(const uint64_t*)b;
    return (ua > ub) - (ua < ub);
}

int main(int argc, char** argv) {
    const char* cfg_path = argc > 1 ? argv[1] : "0tpe.conf";
    int count = argc > 2 ? atoi(argv[2]) : 1000;

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

    otpe_tls_t* tls = otpe_tls_client(sock, cfg.sni);
    if (!tls) {
        fprintf(stderr, "TLS handshake failed\n");
        close(sock);
        return 1;
    }

    uint64_t* rtts = calloc(count, sizeof(uint64_t));
    if (!rtts) return 1;

    printf("Running %d iterations...\n", count);

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

        uint64_t t0 = now_ns();
        if (otpe_tls_send(tls, out, OTPE_HEADER_SIZE) <= 0) break;

        uint8_t in[OTPE_HEADER_SIZE];
        ssize_t n = otpe_tls_recv(tls, in, OTPE_HEADER_SIZE);
        uint64_t t1 = now_ns();

        if (n != OTPE_HEADER_SIZE) break;

        otpe_header_t rep;
        if (!otpe_decode_header(in, n, &rep)) break;
        if (rep.command != OTPE_CMD_PONG) break;

        rtts[ok++] = t1 - t0;
    }

    if (ok == 0) {
        printf("FAIL: no successful pings\n");
        return 1;
    }

    qsort(rtts, ok, sizeof(uint64_t), compare_u64);

    double sum = 0;
    for (int i = 0; i < ok; i++) sum += (double)rtts[i];

    printf("\n=== 0TPE RTT benchmark ===\n");
    printf("iterations: %d (ok=%d)\n", count, ok);
    printf("min:  %.3f ms\n", (double)rtts[0] / 1e6);
    printf("p50:  %.3f ms\n", (double)rtts[ok / 2] / 1e6);
    printf("p95:  %.3f ms\n", (double)rtts[ok * 95 / 100] / 1e6);
    printf("p99:  %.3f ms\n", (double)rtts[ok * 99 / 100] / 1e6);
    printf("max:  %.3f ms\n", (double)rtts[ok - 1] / 1e6);
    printf("avg:  %.3f ms\n", sum / ok / 1e6);

    free(rtts);
    otpe_tls_free(tls);
    close(sock);
    return 0;
}