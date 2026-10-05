#ifndef OTPE_CRYPTO_H
#define OTPE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define OTPE_PUBKEY_SIZE  32
#define OTPE_NONCE_SIZE   12
#define OTPE_TAG_SIZE     16
#define OTPE_EXT_DATA_SIZE (OTPE_PUBKEY_SIZE + OTPE_NONCE_SIZE + OTPE_TAG_SIZE)

int  crypto_load_private_key(const char* path, void** pkey_out);
int  crypto_load_public_key(const char* path, void** pkey_out);
void crypto_free_key(void* pkey);

int crypto_build_extension(void* server_pubkey, uint8_t* out, size_t out_size);
int crypto_verify_extension(void* server_privkey, const uint8_t* data, size_t data_size);

#endif