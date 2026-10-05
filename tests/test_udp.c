#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOCKS_HOST "127.0.0.1"
#define SOCKS_PORT 1080

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
        int r = poll(&pfd, 1, 10000);
        if (r <= 0) return -1;
        ssize_t rd = read(fd, (char*)buf + got, n - got);
        if (rd <= 0) return -1;
        got += (size_t)rd;
    }
    return 0;
}

int main(void) {
    printf("== 0TPE UDP test ==\n");

    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp < 0) { perror("socket tcp"); return 1; }

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(SOCKS_PORT);
    inet_pton(AF_INET, SOCKS_HOST, &sa.sin_addr);

    if (connect(tcp, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect socks");
        return 1;
    }

    uint8_t greet[3] = {0x05, 0x01, 0x00};
    if (write_full(tcp, greet, 3) < 0) { perror("greet"); return 1; }

    uint8_t greet_reply[2];
    if (read_full(tcp, greet_reply, 2) < 0) { perror("greet reply"); return 1; }
    if (greet_reply[0] != 0x05 || greet_reply[1] != 0x00) {
        printf("FAIL: bad greeting reply %02x %02x\n", greet_reply[0], greet_reply[1]);
        return 1;
    }
    printf("[1/4] SOCKS5 greeting OK\n");

    uint8_t assoc[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    if (write_full(tcp, assoc, 10) < 0) { perror("assoc"); return 1; }

    uint8_t assoc_reply[10];
    if (read_full(tcp, assoc_reply, 10) < 0) { perror("assoc reply"); return 1; }
    if (assoc_reply[1] != 0x00) {
        printf("FAIL: UDP ASSOCIATE rep=%02x\n", assoc_reply[1]);
        return 1;
    }

    char udp_ip[64];
    snprintf(udp_ip, sizeof(udp_ip), "%u.%u.%u.%u",
             assoc_reply[4], assoc_reply[5], assoc_reply[6], assoc_reply[7]);
    uint16_t udp_port = (uint16_t)((assoc_reply[8] << 8) | assoc_reply[9]);
    printf("[2/4] UDP relay at %s:%u\n", udp_ip, udp_port);

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) { perror("socket udp"); return 1; }

    struct sockaddr_in ra;
    ra.sin_family = AF_INET;
    ra.sin_port = htons(udp_port);
    inet_pton(AF_INET, udp_ip, &ra.sin_addr);

    uint8_t dns_query[] = {
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

    uint8_t pkt[512];
    size_t p = 0;
    pkt[p++] = 0x00; pkt[p++] = 0x00;
    pkt[p++] = 0x00;
    pkt[p++] = 0x01;
    pkt[p++] = 8; pkt[p++] = 8; pkt[p++] = 8; pkt[p++] = 8;
    pkt[p++] = 0x00; pkt[p++] = 0x35;
    memcpy(pkt + p, dns_query, sizeof(dns_query));
    p += sizeof(dns_query);

    printf("[3/4] sending %zu bytes to %s:%u\n", p, udp_ip, udp_port);
    if (sendto(udp, pkt, p, 0, (struct sockaddr*)&ra, sizeof(ra)) != (ssize_t)p) {
        perror("sendto");
        return 1;
    }

    struct pollfd pfd = { .fd = udp, .events = POLLIN };
    int ready = poll(&pfd, 1, 10000);
    if (ready <= 0) {
        printf("FAIL: timeout waiting for UDP reply\n");
        return 1;
    }

    uint8_t reply[4096];
    ssize_t rn = recvfrom(udp, reply, sizeof(reply), 0, NULL, NULL);
    if (rn < 12) {
        printf("FAIL: short reply %zd bytes\n", rn);
        return 1;
    }

    uint8_t atyp = reply[3];
    size_t hdr = 0;
    if (atyp == 0x01) hdr = 10;
    else if (atyp == 0x04) hdr = 22;
    else if (atyp == 0x03) hdr = 4 + 1 + reply[4] + 2;
    else { printf("FAIL: bad ATYP=0x%02x\n", atyp); return 1; }

    if ((size_t)rn < hdr + 12) {
        printf("FAIL: reply too short after header\n");
        return 1;
    }

    size_t dns_off = hdr;
    uint8_t rcode = reply[dns_off + 3] & 0x0F;
    if (rcode != 0) {
        printf("FAIL: DNS rcode=%u\n", rcode);
        return 1;
    }
    uint16_t ancount = (uint16_t)((reply[dns_off + 6] << 8) | reply[dns_off + 7]);
    if (ancount == 0) {
        printf("FAIL: DNS has 0 answers\n");
        return 1;
    }

    printf("[4/4] DNS reply from 8.8.8.8: rcode=0, ancount=%u\n", ancount);
    printf("\n== SUCCESS: UDP works end-to-end ==\n");
    close(udp);
    close(tcp);
    return 0;
}