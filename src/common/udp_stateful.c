#include "udp_stateful.h"
#include "dns_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

void udp_state_init(udp_target_t* table) {
    memset(table, 0, sizeof(udp_target_t) * UDP_TARGETS_MAX);
    for (int i = 0; i < UDP_TARGETS_MAX; i++) {
        table[i].fd = -1;
    }
}

void udp_state_cleanup(udp_target_t* table) {
    for (int i = 0; i < UDP_TARGETS_MAX; i++) {
        if (table[i].in_use) {
            close(table[i].fd);
            table[i].in_use = 0;
            table[i].fd = -1;
        }
    }
}

int udp_state_find(udp_target_t* table, const char* host, uint16_t port) {
    for (int i = 0; i < UDP_TARGETS_MAX; i++) {
        if (table[i].in_use &&
            table[i].port == port &&
            strcmp(table[i].host, host) == 0) {
            return i;
        }
    }
    return -1;
}

int udp_state_get_or_create(udp_target_t* table, const char* host, uint16_t port) {
    int idx = udp_state_find(table, host, port);
    if (idx >= 0) return idx;

    for (int i = 0; i < UDP_TARGETS_MAX; i++) {
        if (!table[i].in_use) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return -1;

    struct addrinfo* res = dns_cache_lookup(host, port, SOCK_DGRAM);
    if (!res) return -1;

    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    if (fd < 0) return -1;

    strncpy(table[idx].host, host, sizeof(table[idx].host) - 1);
    table[idx].host[sizeof(table[idx].host) - 1] = '\0';
    table[idx].port = port;
    table[idx].fd = fd;
    table[idx].last_seen = time(NULL);
    table[idx].in_use = 1;
    return idx;
}

int udp_state_poll(udp_target_t* table, uint8_t* out, size_t out_size,
                   size_t* out_len, char* out_host, size_t host_size,
                   uint16_t* out_port) {
    *out_len = 0;

    struct pollfd pfds[UDP_TARGETS_MAX];
    int map[UDP_TARGETS_MAX];
    int npfds = 0;

    time_t now = time(NULL);
    for (int i = 0; i < UDP_TARGETS_MAX; i++) {
        if (!table[i].in_use) continue;
        if (now - table[i].last_seen > UDP_TARGET_TIMEOUT_SEC) {
            close(table[i].fd);
            table[i].in_use = 0;
            table[i].fd = -1;
            continue;
        }
        pfds[npfds].fd = table[i].fd;
        pfds[npfds].events = POLLIN;
        pfds[npfds].revents = 0;
        map[npfds] = i;
        npfds++;
    }

    if (npfds == 0) return 0;

    int ready = poll(pfds, npfds, 0);
    if (ready <= 0) return 0;

    for (int k = 0; k < npfds; k++) {
        if (!(pfds[k].revents & POLLIN)) continue;

        int i = map[k];
        uint8_t reply[65536];
        ssize_t rn = recv(table[i].fd, reply, sizeof(reply), 0);
        if (rn <= 0) continue;

        size_t hlen = strlen(table[i].host);
        size_t need = 1 + hlen + 2 + 2 + (size_t)rn;
        if (need > out_size) continue;

        size_t p = 0;
        out[p++] = (uint8_t)hlen;
        memcpy(out + p, table[i].host, hlen);
        p += hlen;
        out[p++] = (uint8_t)((table[i].port >> 8) & 0xFF);
        out[p++] = (uint8_t)(table[i].port & 0xFF);
        out[p++] = (uint8_t)(((size_t)rn >> 8) & 0xFF);
        out[p++] = (uint8_t)((size_t)rn & 0xFF);
        memcpy(out + p, reply, (size_t)rn);
        p += (size_t)rn;

        strncpy(out_host, table[i].host, host_size - 1);
        out_host[host_size - 1] = '\0';
        *out_port = table[i].port;
        *out_len = p;

        table[i].last_seen = now;
        return 1;
    }
    return 0;
}