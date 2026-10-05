#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "protocol.h"

int main() {
    otpe_header_t original;
    original.version  = OTPE_VERSION;
    original.command  = OTPE_CMD_STREAM;
    original.flags    = 0x01;
    original.reserved = 0;
    original.length   = 0;
    original.checksum = 0;
    memset(original.token, 0xCC, OTPE_TOKEN_SIZE);

    uint8_t buf[OTPE_HEADER_SIZE];
    assert(otpe_encode_header(&original, buf, sizeof(buf)));

    otpe_header_t decoded;
    assert(otpe_decode_header(buf, sizeof(buf), &decoded));

    assert(decoded.version  == original.version);
    assert(decoded.command  == original.command);
    assert(decoded.flags    == original.flags);
    assert(decoded.reserved == original.reserved);
    assert(decoded.length   == original.length);
    assert(memcmp(decoded.token, original.token, OTPE_TOKEN_SIZE) == 0);

    printf("Header size: %d bytes (fast handshake)\n", OTPE_HEADER_SIZE);
    printf("All tests passed!\n");
    return 0;
}