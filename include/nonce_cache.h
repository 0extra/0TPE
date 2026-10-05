#ifndef OTPE_NONCE_CACHE_H
#define OTPE_NONCE_CACHE_H

#include <stdint.h>
#include <stddef.h>

void nonce_cache_init(void);
int  nonce_cache_check_and_add(const uint8_t* nonce, size_t nonce_len, uint64_t timestamp);

#endif