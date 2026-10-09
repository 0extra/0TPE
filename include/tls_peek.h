#ifndef OTPE_TLS_PEEK_H
#define OTPE_TLS_PEEK_H

#include <stdint.h>
#include <stddef.h>

int tls_parse_clienthello(const uint8_t* buf, size_t buf_len,
                          char* sni_out, size_t sni_size,
                          int* has_otpe_alpn);

int tls_peek_clienthello(int fd, char* sni_out, size_t sni_size,
                         int* has_otpe_alpn);

#endif