#include "tls.h"
#include "tls_peek.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

struct otpe_tls {
    SSL_CTX* ctx;
    SSL*     ssl;
    int      owns_ctx;
};

static pthread_once_t ssl_once = PTHREAD_ONCE_INIT;
static void* g_client_cert = NULL;
static void* g_client_key = NULL;

static int g_use_session_cache = 0;
static SSL_SESSION* g_cached_session = NULL;
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;

static SSL_CTX* g_client_ctx = NULL;
static pthread_mutex_t g_client_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

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

void otpe_tls_enable_client_session_cache(int enable) {
    g_use_session_cache = enable;
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

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
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

static void load_session_from_disk(void) {
    FILE* f = fopen("tls_session.bin", "rb");
    if (!f) return;
    unsigned char buf[4096];
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (len > 0) {
        const unsigned char* p = buf;
        g_cached_session = d2i_SSL_SESSION(NULL, &p, len);
    }
}

static void save_session_to_disk(SSL_SESSION* session) {
    if (!session) return;
    int len = i2d_SSL_SESSION(session, NULL);
    if (len <= 0 || len > 4096) return;
    unsigned char* buf = malloc(len);
    unsigned char* p = buf;
    i2d_SSL_SESSION(session, &p);
    FILE* f = fopen("tls_session.bin", "wb");
    if (f) {
        fwrite(buf, 1, len, f);
        fclose(f);
    }
    free(buf);
}

void otpe_tls_client_preinit(const char* ca_file) {
    ensure_openssl();
    pthread_mutex_lock(&g_client_ctx_lock);
    if (g_client_ctx) {
        pthread_mutex_unlock(&g_client_ctx_lock);
        return;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        pthread_mutex_unlock(&g_client_ctx_lock);
        return;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        fprintf(stderr, "[tls] cannot load CA file %s\n", ca_file);
        SSL_CTX_free(ctx);
        pthread_mutex_unlock(&g_client_ctx_lock);
        return;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");

#ifdef OPENSSL_IS_BORINGSSL
    SSL_CTX_set_cipher_list(ctx,
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
#else
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
#endif

    SSL_CTX_set1_sigalgs_list(ctx,
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512");

    static const uint8_t alpn_list[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '3'
    };
    SSL_CTX_set_alpn_protos(ctx, alpn_list, sizeof(alpn_list));

    if (g_client_cert && g_client_key) {
        SSL_CTX_use_certificate(ctx, (X509*)g_client_cert);
        SSL_CTX_use_PrivateKey(ctx, (EVP_PKEY*)g_client_key);
    }

    g_client_ctx = ctx;
    load_session_from_disk();
    pthread_mutex_unlock(&g_client_ctx_lock);
}

otpe_tls_t* otpe_tls_client(int fd, const char* sni, const char* ca_file) {
    ensure_openssl();

    pthread_mutex_lock(&g_client_ctx_lock);
    if (!g_client_ctx) {
        pthread_mutex_unlock(&g_client_ctx_lock);
        otpe_tls_client_preinit(ca_file);
        pthread_mutex_lock(&g_client_ctx_lock);
    }
    SSL_CTX* ctx = g_client_ctx;
    pthread_mutex_unlock(&g_client_ctx_lock);

    if (!ctx) return NULL;

    otpe_tls_t* t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->ctx = ctx;
    t->owns_ctx = 0;
    t->ssl = SSL_new(ctx);
    if (!t->ssl) { free(t); return NULL; }

    if (sni && *sni) {
        SSL_set_tlsext_host_name(t->ssl, sni);
        SSL_set1_host(t->ssl, sni);
    }

    if (g_use_session_cache) {
        pthread_mutex_lock(&g_session_lock);
        if (g_cached_session) {
            SSL_set_session(t->ssl, g_cached_session);
        }
        pthread_mutex_unlock(&g_session_lock);
    }

    SSL_set_fd(t->ssl, fd);
    if (SSL_connect(t->ssl) != 1) {
        fprintf(stderr, "[tls] server certificate verification failed\n");
        SSL_free(t->ssl);
        if (t->owns_ctx) SSL_CTX_free(t->ctx);
        free(t);
        return NULL;
    }

    if (g_use_session_cache) {
        pthread_mutex_lock(&g_session_lock);
        if (!SSL_session_reused(t->ssl)) { 
            if (g_cached_session) SSL_SESSION_free(g_cached_session);
            g_cached_session = SSL_get1_session(t->ssl);
            save_session_to_disk(g_cached_session);
        }
        pthread_mutex_unlock(&g_session_lock);
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