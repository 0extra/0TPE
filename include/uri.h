#ifndef OTPE_URI_H
#define OTPE_URI_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

#define URI_MAX 1024

typedef struct {
    uint8_t  token[OTPE_TOKEN_SIZE];
    char     host[256];
    uint16_t port;
    char     sni[256];
    char     name[128];
} otpe_uri_t;

int uri_parse(const char* uri, otpe_uri_t* out);
int uri_generate(const otpe_uri_t* cfg, char* buffer, size_t buffer_size);

#endif