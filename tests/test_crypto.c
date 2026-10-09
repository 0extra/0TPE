#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include "crypto.h"

int main(void) {
    void* a_priv = NULL;
    void* b_priv = NULL;

    assert(crypto_generate_ephemeral(&a_priv) == 0);
    assert(crypto_generate_ephemeral(&b_priv) == 0);
    assert(a_priv != NULL && b_priv != NULL);

    uint8_t a_pub[32];
    uint8_t b_pub[32];
    assert(crypto_get_public_bytes(a_priv, a_pub, sizeof(a_pub)) == 32);
    assert(crypto_get_public_bytes(b_priv, b_pub, sizeof(b_pub)) == 32);
    assert(memcmp(a_pub, b_pub, 32) != 0);

    EVP_PKEY* a_pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, a_pub, 32);
    EVP_PKEY* b_pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, b_pub, 32);
    assert(a_pub_key != NULL && b_pub_key != NULL);

    uint8_t shared_a[64];
    uint8_t shared_b[64];
    size_t shared_a_len = sizeof(shared_a);
    size_t shared_b_len = sizeof(shared_b);

    assert(crypto_derive_shared(a_priv, b_pub_key, shared_a, &shared_a_len) == 0);
    assert(crypto_derive_shared(b_priv, a_pub_key, shared_b, &shared_b_len) == 0);

    assert(shared_a_len == shared_b_len);
    assert(memcmp(shared_a, shared_b, shared_a_len) == 0);

    EVP_PKEY_free(a_pub_key);
    EVP_PKEY_free(b_pub_key);
    crypto_free_key(a_priv);
    crypto_free_key(b_priv);

    printf("All crypto tests passed!\n");
    return 0;
}