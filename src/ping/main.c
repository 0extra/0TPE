#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "protocol.h"
#include "relay.h"
#include "tls.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

int main(int argc, char** argv) {
    const char* ip   = argc > 1 ? argv[1] : "127.0.0.1";
    int         port = argc > 2 ? atoi(argv[2]) : 8443;
    int         cnt  = argc > 3 ? atoi(argv[3]) : 10;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;
    otpe_set_tcp_nodelay(sock);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("Cannot connect\n");
        close(sock); return 1;
    }

    otpe_tls_t* tls = otpe_tls_client(sock, "www.microsoft.com");
    if (!tls) {
        printf("TLS handshake failed\n");
        close(sock); return 1;
    }

    printf("PING 0TPE (TLS) %s:%d\n", ip, port);

    double sum = 0.0;
    int ok = 0;

    for (int i = 0; i < cnt; i++) {
        otpe_header_t req;
        req.version = OTPE_VERSION;
        req.command = OTPE_CMD_PING;
        req.flags = 0;
        req.reserved = 0;
        req.length = 0;
        req.checksum = 0;
        memset(req.token, 0xAB, OTPE_TOKEN_SIZE);

        uint8_t out[OTPE_HEADER_SIZE];
        otpe_encode_header(&req, out, sizeof(out));

        double t0 = now_ms();
        otpe_tls_send(tls, out, OTPE_HEADER_SIZE);

        uint8_t in[OTPE_HEADER_SIZE];
        ssize_t n = otpe_tls_recv(tls, in, OTPE_HEADER_SIZE);
        double t1 = now_ms();

        if (n == OTPE_HEADER_SIZE) {
            otpe_header_t rep;
            if (otpe_decode_header(in, n, &rep) && rep.command == OTPE_CMD_PONG) {
                double rtt = t1 - t0;
                printf("reply from %s: seq=%d time=%.2f ms\n", ip, i, rtt);
                sum += rtt; ok++;
                continue;
            }
        }
        printf("timeout seq=%d\n", i);
    }

    otpe_tls_free(tls);
    close(sock);

    printf("--- %s ping statistics ---\n", ip);
    printf("%d transmitted, %d received\n", cnt, ok);
    if (ok) printf("rtt avg = %.2f ms\n", sum / ok);
    return 0;
}