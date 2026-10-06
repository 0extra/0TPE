#ifndef OTPE_DNS_CACHE_H
#define OTPE_DNS_CACHE_H

#include <stdint.h>
#include <netdb.h>

void dns_cache_init(void);
struct addrinfo* dns_cache_lookup(const char* host, uint16_t port, int socktype);

#endif