#ifndef OTPE_TLS_PEEK_H
#define OTPE_TLS_PEEK_H

#include <stdint.h>
#include <stddef.h>

#define OTPE_EXT_TYPE 0xFFA0

int tls_parse_clienthello(const uint8_t* buf, size_t buf_len,
                          char* sni_out, size_t sni_size,
                          uint8_t* ext_out, size_t ext_size, size_t* ext_len_out);

int tls_peek_clienthello(int fd, char* sni_out, size_t sni_size,
                         uint8_t* ext_out, size_t ext_size, size_t* ext_len_out);

#endif