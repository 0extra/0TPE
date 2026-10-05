#include <stdint.h>
#include <stddef.h>
#include "tls_peek.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char sni[256];
    uint8_t ext[256];
    size_t ext_len = 0;

    tls_parse_clienthello(data, size,
                          sni, sizeof(sni),
                          ext, sizeof(ext), &ext_len);

    return 0;
}