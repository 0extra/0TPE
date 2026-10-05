#include "crypto.h"
#include "nonce_cache.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

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

static int derive_shared(void* privkey, void* peer_pubkey, uint8_t* out, size_t* out_len) {
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

int crypto_build_extension(void* server_pubkey, uint8_t* out, size_t out_size) {
    if (out_size < OTPE_EXT_DATA_SIZE) return -1;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY* eph = NULL;
    if (EVP_PKEY_keygen(ctx, &eph) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY_CTX_free(ctx);

    uint8_t eph_pub[OTPE_PUBKEY_SIZE];
    size_t eph_pub_len = sizeof(eph_pub);
    if (EVP_PKEY_get_raw_public_key(eph, eph_pub, &eph_pub_len) <= 0) {
        EVP_PKEY_free(eph);
        return -1;
    }

    uint8_t shared[64];
    size_t shared_len = sizeof(shared);
    if (derive_shared(eph, server_pubkey, shared, &shared_len) < 0) {
        EVP_PKEY_free(eph);
        return -1;
    }

    uint8_t nonce[OTPE_NONCE_SIZE];
    RAND_bytes(nonce, sizeof(nonce));

    uint64_t ts = (uint64_t)time(NULL);
    uint8_t msg[OTPE_NONCE_SIZE + 8];
    memcpy(msg, nonce, OTPE_NONCE_SIZE);
    for (int i = 0; i < 8; i++)
        msg[OTPE_NONCE_SIZE + i] = (uint8_t)((ts >> (56 - i * 8)) & 0xFF);

    uint8_t tag[OTPE_TAG_SIZE];
    unsigned int tag_len = sizeof(tag);
    HMAC(EVP_sha256(), shared, (int)shared_len, msg, sizeof(msg), tag, &tag_len);

    memcpy(out, eph_pub, OTPE_PUBKEY_SIZE);
    memcpy(out + OTPE_PUBKEY_SIZE, nonce, OTPE_NONCE_SIZE);
    memcpy(out + OTPE_PUBKEY_SIZE + OTPE_NONCE_SIZE, tag, OTPE_TAG_SIZE);

    EVP_PKEY_free(eph);
    return 0;
}

int crypto_verify_extension(void* server_privkey, const uint8_t* data, size_t data_size) {
    if (data_size < OTPE_EXT_DATA_SIZE) return -1;

    const uint8_t* eph_pub = data;
    const uint8_t* nonce   = data + OTPE_PUBKEY_SIZE;
    const uint8_t* tag     = data + OTPE_PUBKEY_SIZE + OTPE_NONCE_SIZE;

    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, eph_pub, OTPE_PUBKEY_SIZE);
    if (!peer) return -1;

    uint8_t shared[64];
    size_t shared_len = sizeof(shared);
    if (derive_shared(server_privkey, peer, shared, &shared_len) < 0) {
        EVP_PKEY_free(peer);
        return -1;
    }
    EVP_PKEY_free(peer);

    uint64_t now = (uint64_t)time(NULL);
    int matched = 0;
    uint64_t matched_ts = 0;

    for (int delta = -30; delta <= 30; delta++) {
        uint64_t cand = now + (int64_t)delta;
        uint8_t msg[OTPE_NONCE_SIZE + 8];
        memcpy(msg, nonce, OTPE_NONCE_SIZE);
        for (int i = 0; i < 8; i++)
            msg[OTPE_NONCE_SIZE + i] = (uint8_t)((cand >> (56 - i * 8)) & 0xFF);

        uint8_t expected[OTPE_TAG_SIZE];
        unsigned int expected_len = sizeof(expected);
        HMAC(EVP_sha256(), shared, (int)shared_len, msg, sizeof(msg), expected, &expected_len);

        if (CRYPTO_memcmp(tag, expected, OTPE_TAG_SIZE) == 0) {
            matched = 1;
            matched_ts = cand;
            break;
        }
    }

    if (!matched) return -1;

    int replay = nonce_cache_check_and_add(nonce, OTPE_NONCE_SIZE, matched_ts);
    if (replay == 1) return -1;
    if (replay < 0) return -1;

    return 0;
}