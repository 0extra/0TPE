#ifndef OTPE_CRYPTO_H
#define OTPE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

int  crypto_load_private_key(const char* path, void** pkey_out);
int  crypto_load_public_key(const char* path, void** pkey_out);
void crypto_free_key(void* pkey);

int crypto_generate_ephemeral(void** pkey_out);
int crypto_get_public_bytes(void* pkey, uint8_t* out, size_t out_size);
int crypto_derive_shared(void* privkey, void* peer_pubkey, uint8_t* out, size_t* out_len);

#endif