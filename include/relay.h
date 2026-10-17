#ifndef RELAY_H
#define RELAY_H

#include "tls.h"
#include <stdint.h>

int  otpe_set_tcp_nodelay(int fd);
void otpe_tune_socket(int fd, int is_server);
void otpe_relay_set_timeouts(uint32_t idle_ms, uint32_t grace_ms);
long otpe_relay_bidirectional(int fd_a, int fd_b);
long otpe_relay_tls_bidirectional(otpe_tls_t* tls, int raw_fd);
int  otpe_connect_timeout(const char* host, uint16_t port);

#endif