#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"
#include "nonce_cache.h"

int main(void) {
    nonce_cache_init();

    system("mkdir -p /tmp/0tpe_test_keys");
    int rc1 = system("openssl genpkey -algorithm X25519 -out /tmp/0tpe_test_keys/server.key 2>/dev/null");
    int rc2 = system("openssl pkey -in /tmp/0tpe_test_keys/server.key -pubout -out /tmp/0tpe_test_keys/server.pub 2>/dev/null");
    assert(rc1 == 0 && rc2 == 0);

    void* privkey = NULL;
    void* pubkey = NULL;

    assert(crypto_load_private_key("/tmp/0tpe_test_keys/server.key", &privkey) == 0);
    assert(crypto_load_public_key("/tmp/0tpe_test_keys/server.pub", &pubkey) == 0);

    uint8_t ext1[OTPE_EXT_DATA_SIZE];
    assert(crypto_build_extension(pubkey, ext1, sizeof(ext1)) == 0);
    assert(crypto_verify_extension(privkey, ext1, sizeof(ext1)) == 0);

    assert(crypto_verify_extension(privkey, ext1, sizeof(ext1)) == -1);

    uint8_t ext2[OTPE_EXT_DATA_SIZE];
    assert(crypto_build_extension(pubkey, ext2, sizeof(ext2)) == 0);
    assert(crypto_verify_extension(privkey, ext2, sizeof(ext2)) == 0);

    uint8_t ext3[OTPE_EXT_DATA_SIZE];
    memcpy(ext3, ext2, sizeof(ext3));
    ext3[OTPE_PUBKEY_SIZE + OTPE_NONCE_SIZE] ^= 0xFF;
    assert(crypto_verify_extension(privkey, ext3, sizeof(ext3)) == -1);

    assert(crypto_verify_extension(privkey, ext2, 10) == -1);

    uint8_t ext4[OTPE_EXT_DATA_SIZE];
    memset(ext4, 0, sizeof(ext4));
    assert(crypto_verify_extension(privkey, ext4, sizeof(ext4)) == -1);

    crypto_free_key(privkey);
    crypto_free_key(pubkey);

    printf("All crypto tests passed!\n");
    return 0;
}