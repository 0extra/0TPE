#ifndef OTPE_CONFIG_H
#define OTPE_CONFIG_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char     listen_ip[64];
    uint16_t listen_port;
    uint32_t max_connections;
    char     cert_file[256];
    char     key_file[256];
    char     ca_file[256];
    char     fallback_sni[256];
    char     log_level[16];
} otpe_server_config_t;

typedef struct {
    char     server_ip[64];
    uint16_t server_port;
    uint16_t socks_port;
    uint16_t http_port;
    uint32_t max_udp_sessions;
    char     sni[256];
    char     token[64];
    char     ca_file[256];
    char     client_cert_file[256];
    char     client_key_file[256];
    char     log_level[16];
} otpe_client_config_t;

int  config_load_server(const char* path, otpe_server_config_t* out);
int  config_load_client(const char* path, otpe_client_config_t* out);
int  config_validate_server(const otpe_server_config_t* cfg);
int  config_validate_client(const otpe_client_config_t* cfg);
int  config_token_to_bytes(const char* token_str, uint8_t* out, size_t out_size);

#endif