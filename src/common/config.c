#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char* trim(char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int parse_line(char* line, char** key, char** value) {
    char* hash = strchr(line, '#');
    if (hash) *hash = '\0';
    char* eq = strchr(line, '=');
    if (!eq) return -1;
    *eq = '\0';
    *key = trim(line);
    *value = trim(eq + 1);
    return (*key[0] && *value[0]) ? 0 : -1;
}

int config_load_server(const char* path, otpe_server_config_t* out) {
    memset(out, 0, sizeof(*out));
    strcpy(out->listen_ip, "0.0.0.0");
    out->listen_port = 8443;
    strcpy(out->cert_file, "certs/server.crt");
    strcpy(out->key_file, "certs/server.key");
    strcpy(out->ca_file, "certs/ca.crt");
    strcpy(out->fallback_sni, "www.microsoft.com");
    strcpy(out->log_level, "info");

    FILE* f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* key, *value;
        if (parse_line(line, &key, &value) != 0) continue;

        if      (strcmp(key, "listen_ip")    == 0) strncpy(out->listen_ip,  value, sizeof(out->listen_ip) - 1);
        else if (strcmp(key, "listen_port")  == 0) out->listen_port = (uint16_t)atoi(value);
        else if (strcmp(key, "cert_file")    == 0) strncpy(out->cert_file,  value, sizeof(out->cert_file) - 1);
        else if (strcmp(key, "key_file")     == 0) strncpy(out->key_file,   value, sizeof(out->key_file) - 1);
        else if (strcmp(key, "ca_file")      == 0) strncpy(out->ca_file,    value, sizeof(out->ca_file) - 1);
        else if (strcmp(key, "fallback_sni") == 0) strncpy(out->fallback_sni, value, sizeof(out->fallback_sni) - 1);
        else if (strcmp(key, "log_level")    == 0) strncpy(out->log_level,  value, sizeof(out->log_level) - 1);
    }
    fclose(f);
    return 0;
}

int config_load_client(const char* path, otpe_client_config_t* out) {
    memset(out, 0, sizeof(*out));
    strcpy(out->server_ip, "127.0.0.1");
    out->server_port = 8443;
    out->socks_port = 1080;
    out->http_port = 8080;
    strcpy(out->sni, "www.microsoft.com");
    strcpy(out->token, "550e8400e29b41d4a716446655440000");
    strcpy(out->client_cert_file, "certs/client.crt");
    strcpy(out->client_key_file, "certs/client.key");
    strcpy(out->log_level, "info");

    FILE* f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* key, *value;
        if (parse_line(line, &key, &value) != 0) continue;

        if      (strcmp(key, "server_ip")        == 0) strncpy(out->server_ip,  value, sizeof(out->server_ip) - 1);
        else if (strcmp(key, "server_port")      == 0) out->server_port = (uint16_t)atoi(value);
        else if (strcmp(key, "socks_port")       == 0) out->socks_port  = (uint16_t)atoi(value);
        else if (strcmp(key, "http_port")        == 0) out->http_port   = (uint16_t)atoi(value);
        else if (strcmp(key, "sni")              == 0) strncpy(out->sni, value, sizeof(out->sni) - 1);
        else if (strcmp(key, "token")            == 0) strncpy(out->token, value, sizeof(out->token) - 1);
        else if (strcmp(key, "client_cert_file") == 0) strncpy(out->client_cert_file, value, sizeof(out->client_cert_file) - 1);
        else if (strcmp(key, "client_key_file")  == 0) strncpy(out->client_key_file, value, sizeof(out->client_key_file) - 1);
        else if (strcmp(key, "log_level")        == 0) strncpy(out->log_level, value, sizeof(out->log_level) - 1);
    }
    fclose(f);
    return 0;
}

int config_token_to_bytes(const char* token_str, uint8_t* out, size_t out_size) {
    size_t len = strlen(token_str);
    size_t j = 0;
    for (size_t i = 0; i < len && j < out_size; i++) {
        if (token_str[i] == '-' || token_str[i] == ' ') continue;
        unsigned int byte;
        if (sscanf(&token_str[i], "%2x", &byte) == 1) {
            out[j++] = (uint8_t)byte;
            i++;
        }
    }
    return (int)j;
}