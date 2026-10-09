#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOCKS_HOST         "127.0.0.1"
#define SOCKS_PORT         1080
#define NUM_CLIENTS        25
#define QUERIES_PER_CLIENT 10
#define QUERY_TIMEOUT_MS   2000
#define INTER_QUERY_US     20000
#define PAYLOAD_LEN        32

typedef struct {
    int      id;
    uint16_t relay_port;
    char     relay_ip[64];
    uint16_t echo_port;
    int      queries_ok;
    int      queries_late;
} client_ctx_t;

static volatile int g_echo_running = 0;
static int g_echo_sock = -1;
static pthread_t g_echo_thread;

static void* echo_server_thread(void* arg) {
    (void)arg;
    uint8_t buf[2048];
    while (g_echo_running) {
        struct pollfd pfd = { .fd = g_echo_sock, .events = POLLIN };
        int r = poll(&pfd, 1, 200);
        if (r <= 0) continue;
        struct sockaddr_storage src;
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(g_echo_sock, buf, sizeof(buf), 0,
                             (struct sockaddr*)&src, &src_len);
        if (n <= 0) continue;
        sendto(g_echo_sock, buf, (size_t)n, 0, (struct sockaddr*)&src, src_len);
    }
    return NULL;
}

static int echo_server_start(uint16_t* out_port) {
    g_echo_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_echo_sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(g_echo_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(g_echo_sock);
        g_echo_sock = -1;
        return -1;
    }
    socklen_t alen = sizeof(addr);
    if (getsockname(g_echo_sock, (struct sockaddr*)&addr, &alen) < 0) {
        close(g_echo_sock);
        g_echo_sock = -1;
        return -1;
    }
    *out_port = ntohs(addr.sin_port);
    g_echo_running = 1;
    if (pthread_create(&g_echo_thread, NULL, echo_server_thread, NULL) != 0) {
        close(g_echo_sock);
        g_echo_sock = -1;
        g_echo_running = 0;
        return -1;
    }
    return 0;
}

static void echo_server_stop(void) {
    if (!g_echo_running) return;
    g_echo_running = 0;
    pthread_join(g_echo_thread, NULL);
    if (g_echo_sock >= 0) close(g_echo_sock);
    g_echo_sock = -1;
}

static int write_full(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int read_full(int fd, void* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int r = poll(&pfd, 1, 5000);
        if (r <= 0) return -1;
        ssize_t rd = read(fd, (char*)buf + got, n - got);
        if (rd <= 0) return -1;
        got += (size_t)rd;
    }
    return 0;
}

static int socks_udp_associate(uint16_t* out_port, char* out_ip, size_t ip_size) {
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp < 0) return -1;
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(SOCKS_PORT);
    inet_pton(AF_INET, SOCKS_HOST, &sa.sin_addr);
    if (connect(tcp, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(tcp);
        return -1;
    }
    uint8_t greet[3] = {0x05, 0x01, 0x00};
    if (write_full(tcp, greet, 3) < 0) { close(tcp); return -1; }
    uint8_t greply[2];
    if (read_full(tcp, greply, 2) < 0) { close(tcp); return -1; }
    if (greply[0] != 0x05 || greply[1] != 0x00) { close(tcp); return -1; }
    uint8_t assoc[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    if (write_full(tcp, assoc, 10) < 0) { close(tcp); return -1; }
    uint8_t rep[10];
    if (read_full(tcp, rep, 10) < 0) { close(tcp); return -1; }
    if (rep[1] != 0x00) { close(tcp); return -1; }
    snprintf(out_ip, ip_size, "%u.%u.%u.%u", rep[4], rep[5], rep[6], rep[7]);
    *out_port = (uint16_t)((rep[8] << 8) | rep[9]);
    return tcp;
}

static size_t build_payload(uint8_t* buf, uint32_t seq) {
    memcpy(buf, "0TPE", 4);
    buf[4] = (uint8_t)(seq >> 24);
    buf[5] = (uint8_t)(seq >> 16);
    buf[6] = (uint8_t)(seq >> 8);
    buf[7] = (uint8_t)(seq & 0xFF);
    for (int i = 8; i < PAYLOAD_LEN; i++) {
        buf[i] = (uint8_t)(seq * 31u + (uint32_t)i);
    }
    return PAYLOAD_LEN;
}

static void drain_udp(int udp) {
    uint8_t tmp[4096];
    for (;;) {
        struct pollfd pfd = { .fd = udp, .events = POLLIN };
        if (poll(&pfd, 1, 0) <= 0) return;
        if (recvfrom(udp, tmp, sizeof(tmp), 0, NULL, NULL) <= 0) return;
    }
}

static int send_and_match(int udp, struct sockaddr_in* relay,
                          uint16_t echo_port, uint32_t seq) {
    uint8_t expected[PAYLOAD_LEN];
    size_t elen = build_payload(expected, seq);

    uint8_t pkt[512];
    size_t p = 0;
    pkt[p++] = 0x00; pkt[p++] = 0x00;
    pkt[p++] = 0x00;
    pkt[p++] = 0x01;
    pkt[p++] = 127; pkt[p++] = 0; pkt[p++] = 0; pkt[p++] = 1;
    pkt[p++] = (uint8_t)((echo_port >> 8) & 0xFF);
    pkt[p++] = (uint8_t)(echo_port & 0xFF);
    memcpy(pkt + p, expected, elen);
    p += elen;

    if (sendto(udp, pkt, p, 0, (struct sockaddr*)relay, sizeof(*relay)) != (ssize_t)p) {
        return -1;
    }

    struct timespec t0, tn;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint8_t reply[4096];
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &tn);
        long elapsed_ms = (tn.tv_sec - t0.tv_sec) * 1000
                        + (tn.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed_ms >= QUERY_TIMEOUT_MS) return -1;

        struct pollfd pfd = { .fd = udp, .events = POLLIN };
        int ready = poll(&pfd, 1, QUERY_TIMEOUT_MS - (int)elapsed_ms);
        if (ready <= 0) return -1;

        ssize_t rn = recvfrom(udp, reply, sizeof(reply), 0, NULL, NULL);
        if (rn < 12) continue;
        if (reply[0] != 0x00 || reply[1] != 0x00) continue;

        uint8_t atyp = reply[3];
        size_t hdr;
        if (atyp == 0x01) hdr = 10;
        else if (atyp == 0x04) hdr = 22;
        else if (atyp == 0x03) hdr = 4 + 1 + reply[4] + 2;
        else continue;

        if ((size_t)rn < hdr) continue;
        size_t dlen = (size_t)rn - hdr;
        if (dlen != elen) continue;
        if (memcmp(reply + hdr, expected, elen) != 0) continue;

        return 0;
    }
}

static void* worker(void* arg) {
    client_ctx_t* ctx = (client_ctx_t*)arg;

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) return NULL;

    struct sockaddr_in relay;
    memset(&relay, 0, sizeof(relay));
    relay.sin_family = AF_INET;
    relay.sin_port = htons(ctx->relay_port);
    inet_pton(AF_INET, ctx->relay_ip, &relay.sin_addr);

    for (int q = 0; q < QUERIES_PER_CLIENT; q++) {
        uint32_t seq = ((uint32_t)ctx->id << 16) | (uint32_t)q;
        drain_udp(udp);
        if (send_and_match(udp, &relay, ctx->echo_port, seq) == 0) {
            ctx->queries_ok++;
        }
        usleep(INTER_QUERY_US);
    }

    close(udp);
    return NULL;
}

int main(void) {
    printf("== 0TPE UDP stress test (%d clients x %d queries) ==\n",
           NUM_CLIENTS, QUERIES_PER_CLIENT);

    uint16_t echo_port = 0;
    if (echo_server_start(&echo_port) < 0) {
        printf("FAIL: cannot start local echo server\n");
        return 1;
    }
    printf("Local echo server on 127.0.0.1:%u\n", echo_port);

    uint16_t relay_port = 0;
    char relay_ip[64] = {0};
    int tcp = socks_udp_associate(&relay_port, relay_ip, sizeof(relay_ip));
    if (tcp < 0) {
        printf("FAIL: SOCKS5 UDP ASSOCIATE failed (is otpe-client running?)\n");
        echo_server_stop();
        return 1;
    }
    printf("UDP relay at %s:%u\n", relay_ip, relay_port);

    pthread_t threads[NUM_CLIENTS];
    client_ctx_t ctxs[NUM_CLIENTS];

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < NUM_CLIENTS; i++) {
        ctxs[i].id = i;
        ctxs[i].relay_port = relay_port;
        snprintf(ctxs[i].relay_ip, sizeof(ctxs[i].relay_ip), "%s", relay_ip);
        ctxs[i].echo_port = echo_port;
        ctxs[i].queries_ok = 0;
        ctxs[i].queries_late = 0;
        if (pthread_create(&threads[i], NULL, worker, &ctxs[i]) != 0) {
            printf("FAIL: pthread_create for client %d\n", i);
            close(tcp);
            echo_server_stop();
            return 1;
        }
    }

    for (int i = 0; i < NUM_CLIENTS; i++) pthread_join(threads[i], NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    int total_ok = 0;
    int clients_full = 0;
    for (int i = 0; i < NUM_CLIENTS; i++) {
        total_ok += ctxs[i].queries_ok;
        if (ctxs[i].queries_ok == QUERIES_PER_CLIENT) clients_full++;
    }
    int logical = NUM_CLIENTS * QUERIES_PER_CLIENT;
    double loss_pct = 100.0 * (logical - total_ok) / logical;

    printf("\n--- stress statistics ---\n");
    printf("clients:      %d (%d with 100%% success)\n", NUM_CLIENTS, clients_full);
    printf("queries:      %d\n", logical);
    printf("success:      %d/%d\n", total_ok, logical);
    printf("elapsed:      %.2f s\n", elapsed);
    printf("throughput:   %.1f queries/s\n", total_ok / elapsed);
    printf("loss:         %.2f%%\n", loss_pct);

    close(tcp);
    echo_server_stop();

    if (total_ok == logical) {
        printf("\n== SUCCESS: all %d queries echoed back correctly ==\n", logical);
        return 0;
    }
    printf("\n== FAIL: %d/%d failed ==\n", logical - total_ok, logical);
    return 1;
}