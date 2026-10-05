#ifndef OTPE_HTTP_PROXY_H
#define OTPE_HTTP_PROXY_H

#include <stdint.h>
#include <stddef.h>

int http_connect_handshake(int fd, char* out_host, size_t host_size, uint16_t* out_port);

#endif