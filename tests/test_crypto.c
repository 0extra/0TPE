#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"

int main(void) {
    system("mkdir -p /tmp/0tpe_test_keys");

    assert(system("openssl ecparam -name prime256v1 -genkey -noout "
                  "-out /tmp/0tpe_test_keys/server.key 2>/dev/null") == 0);
    assert(system("openssl req -new -x509 -key /tmp/0tpe_test_keys/server.key "
                  "-subj /CN=test-server -days 1 "
                  "-out /tmp/0tpe_test_keys/server.crt 2>/dev/null") == 0);

    assert(system("openssl genpkey -algorithm X25519 "
                  "-out /tmp/0tpe_test_keys/x25519.key 2>/dev/null") == 0);
    assert(system("openssl pkey -in /tmp/0tpe_test_keys/x25519.key -pubout "
                  "-out /tmp/0tpe_test_keys/x25519.pub 2>/dev/null") == 0);

    void* server_priv = NULL;
    assert(crypto_load_private_key("/tmp/0tpe_test_keys/server.key", &server_priv) == 0);
    assert(server_priv != NULL);

    void* x25519_pub = NULL;
    assert(crypto_load_public_key("/tmp/0tpe_test_keys/x25519.pub", &x25519_pub) == 0);
    assert(x25519_pub != NULL);

    void* eph_a = NULL;
    void* eph_b = NULL;
    assert(crypto_generate_ephemeral(&eph_a) == 0);
    assert(crypto_generate_ephemeral(&eph_b) == 0);
    assert(eph_a != NULL && eph_b != NULL);

    uint8_t pub_a[64];
    uint8_t pub_b[64];
    int len_a = crypto_get_public_bytes(eph_a, pub_a, sizeof(pub_a));
    int len_b = crypto_get_public_bytes(eph_b, pub_b, sizeof(pub_b));
    assert(len_a == 32);
    assert(len_b == 32);
    assert(memcmp(pub_a, pub_b, 32) != 0);

    uint8_t shared_a[64];
    uint8_t shared_b[64];
    size_t shared_a_len = sizeof(shared_a);
    size_t shared_b_len = sizeof(shared_b);

    void* pub_b_key = NULL;
    void* pub_a_key = NULL;

    assert(system("cp /tmp/0tpe_test_keys/x25519.pub /tmp/0tpe_test_keys/pub_b.pub") == 0);

    assert(system("openssl pkey -pubin -in /tmp/0tpe_test_keys/x25519.pub "
                  "-outform DER -out /tmp/0tpe_test_keys/tmp.der 2>/dev/null") == 0);

    FILE* f = fopen("/tmp/0tpe_test_keys/pub_a.pub", "w");
    assert(f != NULL);
    fprintf(f, "-----BEGIN PUBLIC KEY-----\n");

    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t der[64];
    der[0] = 0x30; der[1] = 0x2a;
    der[2] = 0x30; der[3] = 0x05;
    der[4] = 0x06; der[5] = 0x03;
    der[6] = 0x2b; der[7] = 0x65; der[8] = 0x6e;
    der[9] = 0x03; der[10] = 0x21; der[11] = 0x00;
    memcpy(der + 12, pub_a, 32);

    int i = 0;
    while (i < 44) {
        uint32_t v = 0;
        int n = 0;
        for (int k = 0; k < 3 && i + k < 44; k++) {
            v = (v << 8) | der[i + k];
            n++;
        }
        v <<= (3 - n) * 8;
        for (int k = 0; k < 4; k++) {
            if (k <= n) {
                fputc(b64[(v >> (18 - k * 6)) & 0x3f], f);
            } else {
                fputc('=', f);
            }
        }
        i += 3;
    }
    fprintf(f, "\n-----END PUBLIC KEY-----\n");
    fclose(f);

    assert(crypto_load_public_key("/tmp/0tpe_test_keys/pub_a.pub", &pub_a_key) == 0);
    assert(crypto_load_public_key("/tmp/0tpe_test_keys/pub_b.pub", &pub_b_key) == 0);

    assert(crypto_derive_shared(eph_a, pub_b_key, shared_a, &shared_a_len) == 0);
    assert(crypto_derive_shared(eph_b, pub_a_key, shared_b, &shared_b_len) == 0);

    assert(shared_a_len == shared_b_len);
    assert(memcmp(shared_a, shared_b, shared_a_len) == 0);

    crypto_free_key(server_priv);
    crypto_free_key(x25519_pub);
    crypto_free_key(eph_a);
    crypto_free_key(eph_b);
    crypto_free_key(pub_a_key);
    crypto_free_key(pub_b_key);

    printf("All crypto tests passed!\n");
    return 0;
}