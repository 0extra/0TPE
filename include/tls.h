#ifndef OTPE_TLS_H
#define OTPE_TLS_H

#include <stddef.h>
#include <sys/types.h>

typedef struct otpe_tls otpe_tls_t;

otpe_tls_t* otpe_tls_server(int fd, const char* cert_file, const char* key_file);
otpe_tls_t* otpe_tls_client(int fd, const char* sni);
void        otpe_tls_free(otpe_tls_t* t);

ssize_t otpe_tls_send(otpe_tls_t* t, const void* buf, size_t len);
ssize_t otpe_tls_recv(otpe_tls_t* t, void* buf, size_t len);

int otpe_tls_get_fd(otpe_tls_t* t);
int otpe_tls_pending(otpe_tls_t* t);

void otpe_tls_init(void);
void otpe_tls_set_server_pubkey(void* pkey);

#endif