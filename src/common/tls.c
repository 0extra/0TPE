#include "tls.h"
#include "tls_peek.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

struct otpe_tls {
    SSL_CTX* ctx;
    SSL*     ssl;
};

static pthread_once_t ssl_once = PTHREAD_ONCE_INIT;
static void* g_server_pubkey = NULL;

static void ssl_init_fn(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void otpe_tls_init(void) {
    pthread_once(&ssl_once, ssl_init_fn);
}

void otpe_tls_set_server_pubkey(void* pkey) {
    g_server_pubkey = pkey;
}

static void ensure_openssl(void) {
    pthread_once(&ssl_once, ssl_init_fn);
}

static int otpe_ext_add_cb(SSL *s, unsigned int ext_type, unsigned int context,
                           const unsigned char **out, size_t *outlen,
                           X509 *x, size_t chainidx, int *al, void *arg) {
    (void)s; (void)ext_type; (void)context; (void)x; (void)chainidx; (void)al; (void)arg;
    static __thread uint8_t data[OTPE_EXT_DATA_SIZE];
    if (!g_server_pubkey) return 0;
    if (crypto_build_extension(g_server_pubkey, data, sizeof(data)) != 0) return 0;
    *out = data;
    *outlen = sizeof(data);
    return 1;
}

otpe_tls_t* otpe_tls_server(int fd, const char* cert_file, const char* key_file) {
    ensure_openssl();
    otpe_tls_t* t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->ctx = SSL_CTX_new(TLS_server_method());
    if (!t->ctx) { free(t); return NULL; }

    SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(t->ctx, SSL_OP_NO_COMPRESSION);

    if (SSL_CTX_use_certificate_file(t->ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(t->ctx); free(t); return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(t->ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(t->ctx); free(t); return NULL;
    }

    t->ssl = SSL_new(t->ctx);
    if (!t->ssl) { SSL_CTX_free(t->ctx); free(t); return NULL; }

    SSL_set_fd(t->ssl, fd);
    if (SSL_accept(t->ssl) != 1) {
        SSL_free(t->ssl); SSL_CTX_free(t->ctx); free(t); return NULL;
    }
    return t;
}

otpe_tls_t* otpe_tls_client(int fd, const char* sni) {
    ensure_openssl();
    otpe_tls_t* t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx) { free(t); return NULL; }

    SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL);

    SSL_CTX_set1_groups_list(t->ctx, "X25519:P-256:P-384");
    SSL_CTX_set_ciphersuites(t->ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(t->ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
    SSL_CTX_set1_sigalgs_list(t->ctx,
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512");

    SSL_CTX_add_custom_ext(t->ctx, OTPE_EXT_TYPE,
                           SSL_EXT_CLIENT_HELLO,
                           otpe_ext_add_cb, NULL, NULL, NULL, NULL);

    t->ssl = SSL_new(t->ctx);
    if (!t->ssl) { SSL_CTX_free(t->ctx); free(t); return NULL; }

    if (sni && *sni) {
        SSL_set_tlsext_host_name(t->ssl, sni);
    }

    SSL_set_fd(t->ssl, fd);
    if (SSL_connect(t->ssl) != 1) {
        SSL_free(t->ssl); SSL_CTX_free(t->ctx); free(t); return NULL;
    }
    return t;
}

void otpe_tls_free(otpe_tls_t* t) {
    if (!t) return;
    if (t->ssl) { SSL_shutdown(t->ssl); SSL_free(t->ssl); }
    if (t->ctx) SSL_CTX_free(t->ctx);
    free(t);
}

ssize_t otpe_tls_send(otpe_tls_t* t, const void* buf, size_t len) {
    return SSL_write(t->ssl, buf, (int)len);
}

ssize_t otpe_tls_recv(otpe_tls_t* t, void* buf, size_t len) {
    return SSL_read(t->ssl, buf, (int)len);
}

int otpe_tls_get_fd(otpe_tls_t* t) {
    return SSL_get_fd(t->ssl);
}

int otpe_tls_pending(otpe_tls_t* t) {
    return SSL_pending(t->ssl);
}