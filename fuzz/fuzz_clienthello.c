#include <stdint.h>
#include <stddef.h>
#include "tls_peek.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char sni[256];
    int has_otpe_alpn = 0;

    tls_parse_clienthello(data, size,
                          sni, sizeof(sni),
                          &has_otpe_alpn);

    return 0;
}