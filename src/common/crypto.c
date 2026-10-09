#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

int crypto_load_private_key(const char* path, void** pkey_out) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) return -1;
    *pkey_out = pkey;
    return 0;
}

int crypto_load_public_key(const char* path, void** pkey_out) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    EVP_PKEY* pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) return -1;
    *pkey_out = pkey;
    return 0;
}

void crypto_free_key(void* pkey) {
    if (pkey) EVP_PKEY_free((EVP_PKEY*)pkey);
}

int crypto_generate_ephemeral(void** pkey_out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY_CTX_free(ctx);
    *pkey_out = pkey;
    return 0;
}

int crypto_get_public_bytes(void* pkey, uint8_t* out, size_t out_size) {
    size_t len = out_size;
    if (EVP_PKEY_get_raw_public_key((EVP_PKEY*)pkey, out, &len) <= 0) return -1;
    return (int)len;
}

int crypto_derive_shared(void* privkey, void* peer_pubkey, uint8_t* out, size_t* out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) return -1;
    if (EVP_PKEY_derive_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_derive_set_peer(ctx, peer_pubkey) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    size_t len = 0;
    if (EVP_PKEY_derive(ctx, NULL, &len) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (len > *out_len) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_derive(ctx, out, &len) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    *out_len = len;
    EVP_PKEY_CTX_free(ctx);
    return 0;
}