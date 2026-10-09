#include "tls.h"
#include "tls_peek.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct otpe_tls {
    SSL_CTX* ctx;
    SSL*     ssl;
    int      owns_ctx;
};

static pthread_once_t ssl_once = PTHREAD_ONCE_INIT;
static void* g_client_cert = NULL;
static void* g_client_key = NULL;

static void ssl_init_fn(void) {
#ifdef OPENSSL_IS_BORINGSSL
    (void)0;
#else
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
}

void otpe_tls_init(void) {
    pthread_once(&ssl_once, ssl_init_fn);
}

void otpe_tls_set_client_cert(void* cert, void* key) {
    g_client_cert = cert;
    g_client_key = key;
}

static void ensure_openssl(void) {
    pthread_once(&ssl_once, ssl_init_fn);
}

static SSL_CTX* g_server_ctx = NULL;
static pthread_mutex_t g_server_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

void otpe_tls_server_preinit(const char* cert_file, const char* key_file,
                             const char* ca_file) {
    ensure_openssl();
    pthread_mutex_lock(&g_server_ctx_lock);
    if (g_server_ctx) {
        pthread_mutex_unlock(&g_server_ctx_lock);
        return;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        pthread_mutex_unlock(&g_server_ctx_lock);
        return;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        pthread_mutex_unlock(&g_server_ctx_lock);
        return;
    }

    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        SSL_CTX_free(ctx);
        pthread_mutex_unlock(&g_server_ctx_lock);
        return;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    g_server_ctx = ctx;
    pthread_mutex_unlock(&g_server_ctx_lock);
}

otpe_tls_t* otpe_tls_server(int fd, const char* cert_file, const char* key_file,
                            const char* ca_file) {
    ensure_openssl();

    pthread_mutex_lock(&g_server_ctx_lock);
    if (!g_server_ctx) {
        pthread_mutex_unlock(&g_server_ctx_lock);
        otpe_tls_server_preinit(cert_file, key_file, ca_file);
        pthread_mutex_lock(&g_server_ctx_lock);
    }
    SSL_CTX* ctx = g_server_ctx;
    pthread_mutex_unlock(&g_server_ctx_lock);

    if (!ctx) return NULL;

    otpe_tls_t* t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->ctx = ctx;
    t->owns_ctx = 0;
    t->ssl = SSL_new(ctx);
    if (!t->ssl) { free(t); return NULL; }

    SSL_set_fd(t->ssl, fd);
    if (SSL_accept(t->ssl) != 1) {
        SSL_free(t->ssl);
        free(t);
        return NULL;
    }
    return t;
}

otpe_tls_t* otpe_tls_client(int fd, const char* sni) {
    ensure_openssl();
    otpe_tls_t* t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx) { free(t); return NULL; }
    t->owns_ctx = 1;

    SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL);

    SSL_CTX_set1_groups_list(t->ctx, "X25519:P-256:P-384");

#ifdef OPENSSL_IS_BORINGSSL
    SSL_CTX_set_cipher_list(t->ctx,
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
#else
    SSL_CTX_set_ciphersuites(t->ctx,
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(t->ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
#endif

    SSL_CTX_set1_sigalgs_list(t->ctx,
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512");

    static const uint8_t alpn_list[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        4, '0', 't', 'p', 'e'
    };
    SSL_CTX_set_alpn_protos(t->ctx, alpn_list, sizeof(alpn_list));

    if (g_client_cert && g_client_key) {
        SSL_CTX_use_certificate(t->ctx, (X509*)g_client_cert);
        SSL_CTX_use_PrivateKey(t->ctx, (EVP_PKEY*)g_client_key);
    }

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
    if (t->ssl) {
        int fd = SSL_get_fd(t->ssl);
        if (fd >= 0) {
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl);
    }
    if (t->ctx && t->owns_ctx) SSL_CTX_free(t->ctx);
    free(t);
}

ssize_t otpe_tls_send(otpe_tls_t* t, const void* buf, size_t len) {
    return SSL_write(t->ssl, buf, (int)len);
}

ssize_t otpe_tls_recv(otpe_tls_t* t, void* buf, size_t len) {
    return SSL_read(t->ssl, buf, (int)len);
}

ssize_t otpe_tls_send_all(otpe_tls_t* t, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < len) {
        int w = SSL_write(t->ssl, p + sent, (int)(len - sent));
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return (ssize_t)sent;
}

ssize_t otpe_tls_recv_all(otpe_tls_t* t, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t got = 0;
    while (got < len) {
        int r = SSL_read(t->ssl, p + got, (int)(len - got));
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

int otpe_tls_get_fd(otpe_tls_t* t) { return SSL_get_fd(t->ssl); }
int otpe_tls_pending(otpe_tls_t* t) { return SSL_pending(t->ssl); }