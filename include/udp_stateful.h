#ifndef OTPE_UDP_STATEFUL_H
#define OTPE_UDP_STATEFUL_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <netdb.h>
#include "tls.h"

#define UDP_TARGETS_MAX 64
#define UDP_TARGET_TIMEOUT_SEC 60

typedef struct {
    char     host[256];
    uint16_t port;
    int      fd;
    time_t   last_seen;
    int      in_use;
} udp_target_t;

void udp_state_init(udp_target_t* table);
void udp_state_cleanup(udp_target_t* table);

int udp_state_find(udp_target_t* table, const char* host, uint16_t port);
int udp_state_get_or_create(udp_target_t* table, const char* host, uint16_t port);

int udp_state_poll(udp_target_t* table, uint8_t* out, size_t out_size,
                   size_t* out_len, char* out_host, size_t host_size,
                   uint16_t* out_port);

#endif