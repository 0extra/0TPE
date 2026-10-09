#ifndef OTPE_TLS_H
#define OTPE_TLS_H

#include <stddef.h>
#include <sys/types.h>

typedef struct otpe_tls otpe_tls_t;

otpe_tls_t* otpe_tls_server(int fd, const char* cert_file, const char* key_file,
                            const char* ca_file);
otpe_tls_t* otpe_tls_client(int fd, const char* sni, const char* ca_file);
void        otpe_tls_free(otpe_tls_t* t);

void        otpe_tls_server_preinit(const char* cert_file, const char* key_file,
                                    const char* ca_file);
void        otpe_tls_set_client_cert(void* cert, void* key);

ssize_t otpe_tls_send(otpe_tls_t* t, const void* buf, size_t len);
ssize_t otpe_tls_recv(otpe_tls_t* t, void* buf, size_t len);
ssize_t otpe_tls_send_all(otpe_tls_t* t, const void* buf, size_t len);
ssize_t otpe_tls_recv_all(otpe_tls_t* t, void* buf, size_t len);

int otpe_tls_get_fd(otpe_tls_t* t);
int otpe_tls_pending(otpe_tls_t* t);

void otpe_tls_init(void);

#endif