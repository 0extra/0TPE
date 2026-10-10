#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
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

#define DEFAULT_WORKERS 8
#define DEFAULT_PER_WORKER 25

static otpe_client_config_t g_cfg;
static uint8_t g_token[OTPE_TOKEN_SIZE];
static uint64_t g_ok = 0;
static uint64_t g_fail = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t read_status_field(const char* key) {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    uint64_t val = 0;
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) == 0) {
            sscanf(line + klen, "%lu", &val);
            break;
        }
    }
    fclose(f);
    return val;
}

static int connect_and_ping(void) {
    int sock = otpe_connect_timeout(g_cfg.server_ip, g_cfg.server_port);
    if (sock < 0) return -1;
    otpe_set_tcp_nodelay(sock);

    otpe_tls_t* tls = otpe_tls_client(sock, g_cfg.sni, g_cfg.ca_file);
    if (!tls) {
        close(sock);
        return -1;
    }

    otpe_header_t req;
    req.version  = OTPE_VERSION;
    req.command  = OTPE_CMD_PING;
    req.flags    = 0;
    req.reserved = 0;
    req.length   = 0;
    req.checksum = 0;
    memcpy(req.token, g_token, OTPE_TOKEN_SIZE);

    uint8_t out[OTPE_HEADER_SIZE];
    otpe_encode_header(&req, out, sizeof(out));

    if (otpe_tls_send_all(tls, out, OTPE_HEADER_SIZE) <= 0) {
        otpe_tls_free(tls);
        close(sock);
        return -1;
    }

    uint8_t in[OTPE_HEADER_SIZE];
    if (otpe_tls_recv_all(tls, in, OTPE_HEADER_SIZE) != OTPE_HEADER_SIZE) {
        otpe_tls_free(tls);
        close(sock);
        return -1;
    }

    otpe_header_t rep;
    int ok = otpe_decode_header(in, OTPE_HEADER_SIZE, &rep) &&
             rep.command == OTPE_CMD_PONG;

    otpe_tls_free(tls);
    close(sock);
    return ok ? 0 : -1;
}

typedef struct { int count; } worker_arg_t;

static void* worker(void* arg) {
    worker_arg_t* wa = (worker_arg_t*)arg;
    uint64_t ok = 0, fail = 0;
    for (int i = 0; i < wa->count; i++) {
        if (connect_and_ping() == 0) ok++;
        else fail++;
    }
    pthread_mutex_lock(&g_lock);
    g_ok += ok;
    g_fail += fail;
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

int main(int argc, char** argv) {
    const char* cfg_path = argc > 1 ? argv[1] : "0tpe.conf";
    int workers = argc > 2 ? atoi(argv[2]) : DEFAULT_WORKERS;
    int per_worker = argc > 3 ? atoi(argv[3]) : DEFAULT_PER_WORKER;

    if (config_load_client(cfg_path, &g_cfg) != 0) return 1;
    if (config_validate_client(&g_cfg) != 0) return 1;

    config_token_to_bytes(g_cfg.token, g_token, OTPE_TOKEN_SIZE);

    FILE* certf = fopen(g_cfg.client_cert_file, "r");
    if (!certf) { fprintf(stderr, "no client cert\n"); return 1; }
    X509* cert = PEM_read_X509(certf, NULL, NULL, NULL);
    fclose(certf);
    FILE* keyf = fopen(g_cfg.client_key_file, "r");
    if (!keyf) { fprintf(stderr, "no client key\n"); return 1; }
    EVP_PKEY* key = PEM_read_PrivateKey(keyf, NULL, NULL, NULL);
    fclose(keyf);
    if (!cert || !key) return 1;

    otpe_tls_set_client_cert(cert, key);
    otpe_tls_init();
    dns_cache_init();

    int total = workers * per_worker;

    uint64_t mem_kb_before = read_status_field("VmRSS:");
    struct timespec cpu_before, cpu_after;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_before);

    printf("=== 0TPE connection benchmark ===\n");
    printf("workers:  %d\n", workers);
    printf("per worker: %d\n", per_worker);
    printf("total:    %d\n\n", total);

    pthread_t* threads = calloc(workers, sizeof(pthread_t));
    worker_arg_t* args = calloc(workers, sizeof(worker_arg_t));

    uint64_t t0 = now_ns();
    for (int i = 0; i < workers; i++) {
        args[i].count = per_worker;
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }
    for (int i = 0; i < workers; i++) pthread_join(threads[i], NULL);
    uint64_t t1 = now_ns();

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_after);
    uint64_t mem_kb_after = read_status_field("VmRSS:");

    double wall_s = (double)(t1 - t0) / 1e9;
    double cpu_s = (cpu_after.tv_sec - cpu_before.tv_sec)
                 + (cpu_after.tv_nsec - cpu_before.tv_nsec) / 1e9;

    printf("ok:       %lu\n", (unsigned long)g_ok);
    printf("fail:     %lu\n", (unsigned long)g_fail);
    printf("elapsed:  %.3f s\n", wall_s);
    printf("conn/s:   %.1f\n", g_ok / wall_s);
    printf("cpu:      %.2f s (%.0f%% of wall)\n", cpu_s, 100.0 * cpu_s / wall_s);
    printf("rss:      %lu KB -> %lu KB (+%ld KB)\n",
           (unsigned long)mem_kb_before,
           (unsigned long)mem_kb_after,
           (long)(mem_kb_after - mem_kb_before));

    free(threads);
    free(args);
    return g_fail == 0 ? 0 : 1;
}