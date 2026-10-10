#include "config.h"
#include "protocol.h"
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

static int parse_port(const char* s, uint16_t* out, const char* name) {
    char* end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0') {
        fprintf(stderr, "config: %s: invalid number '%s'\n", name, s);
        return -1;
    }
    if (v < 1 || v > 65535) {
        fprintf(stderr, "config: %s: port out of range (1-65535): %ld\n", name, v);
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

static int parse_u32(const char* s, uint32_t* out, const char* name,
                     uint32_t min_v, uint32_t max_v) {
    char* end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0') {
        fprintf(stderr, "config: %s: invalid number '%s'\n", name, s);
        return -1;
    }
    if (v < (long)min_v || v > (long)max_v) {
        fprintf(stderr, "config: %s: out of range (%u-%u): %ld\n", name, min_v, max_v, v);
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int file_readable(const char* path) {
    if (!path || !path[0]) return 0;
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    fclose(f);
    return 1;
}

static int validate_token_hex(const char* token) {
    if (!token) return -1;
    size_t len = strlen(token);
    int nibbles = 0;
    for (size_t i = 0; i < len; i++) {
        char c = token[i];
        if (c == '-' || c == ' ') continue;
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) {
            nibbles++;
        } else {
            return -1;
        }
    }
    return nibbles >= OTPE_TOKEN_SIZE * 2 ? 0 : -1;
}

static int valid_log_level(const char* s) {
    return s && (strcmp(s, "debug") == 0 ||
                 strcmp(s, "info")  == 0 ||
                 strcmp(s, "warn")  == 0 ||
                 strcmp(s, "error") == 0);
}

int config_load_server(const char* path, otpe_server_config_t* out) {
    memset(out, 0, sizeof(*out));
    strcpy(out->listen_ip, "0.0.0.0");
    out->listen_port = 8443;
    out->max_connections = 512;
    strcpy(out->cert_file, "certs/server.crt");
    strcpy(out->key_file, "certs/server.key");
    strcpy(out->ca_file, "certs/ca.crt");
    strcpy(out->fallback_sni, "www.microsoft.com");
    strcpy(out->log_level, "info");

    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "config: cannot open %s\n", path);
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* key;
        char* value;
        if (parse_line(line, &key, &value) != 0) continue;

        if      (strcmp(key, "listen_ip")    == 0) strncpy(out->listen_ip,  value, sizeof(out->listen_ip) - 1);
        else if (strcmp(key, "listen_port")  == 0) {
            if (parse_port(value, &out->listen_port, "listen_port") < 0) { fclose(f); return -1; }
        }
        else if (strcmp(key, "max_connections") == 0) {
            if (parse_u32(value, &out->max_connections, "max_connections", 1, 65535) < 0) { fclose(f); return -1; }
        }
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
    out->max_udp_sessions = 32;
    strcpy(out->sni, "www.microsoft.com");
    strcpy(out->token, "550e8400e29b41d4a716446655440000");
    strcpy(out->ca_file, "certs/ca.crt");
    strcpy(out->client_cert_file, "certs/client.crt");
    strcpy(out->client_key_file, "certs/client.key");
    strcpy(out->log_level, "info");

    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "config: cannot open %s\n", path);
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* key;
        char* value;
        if (parse_line(line, &key, &value) != 0) continue;

        if      (strcmp(key, "server_ip")        == 0) strncpy(out->server_ip,  value, sizeof(out->server_ip) - 1);
        else if (strcmp(key, "server_port")      == 0) {
            if (parse_port(value, &out->server_port, "server_port") < 0) { fclose(f); return -1; }
        }
        else if (strcmp(key, "socks_port")       == 0) {
            if (parse_port(value, &out->socks_port, "socks_port") < 0) { fclose(f); return -1; }
        }
        else if (strcmp(key, "http_port")        == 0) {
            if (parse_port(value, &out->http_port, "http_port") < 0) { fclose(f); return -1; }
        }
        else if (strcmp(key, "max_udp_sessions") == 0) {
            if (parse_u32(value, &out->max_udp_sessions, "max_udp_sessions", 1, 256) < 0) { fclose(f); return -1; }
        }
        else if (strcmp(key, "sni")              == 0) strncpy(out->sni, value, sizeof(out->sni) - 1);
        else if (strcmp(key, "token")            == 0) strncpy(out->token, value, sizeof(out->token) - 1);
        else if (strcmp(key, "ca_file")          == 0) strncpy(out->ca_file, value, sizeof(out->ca_file) - 1);
        else if (strcmp(key, "client_cert_file") == 0) strncpy(out->client_cert_file, value, sizeof(out->client_cert_file) - 1);
        else if (strcmp(key, "client_key_file")  == 0) strncpy(out->client_key_file, value, sizeof(out->client_key_file) - 1);
        else if (strcmp(key, "log_level")        == 0) strncpy(out->log_level, value, sizeof(out->log_level) - 1);
    }
    fclose(f);
    return 0;
}

int config_validate_server(const otpe_server_config_t* cfg) {
    if (!cfg) return -1;
    if (cfg->listen_ip[0] == '\0') {
        fprintf(stderr, "config: listen_ip is empty\n");
        return -1;
    }
    if (cfg->fallback_sni[0] == '\0') {
        fprintf(stderr, "config: fallback_sni is empty\n");
        return -1;
    }
    if (cfg->max_connections < 1) {
        fprintf(stderr, "config: max_connections must be at least 1\n");
        return -1;
    }
    if (!file_readable(cfg->cert_file)) {
        fprintf(stderr, "config: cert_file not readable: %s\n", cfg->cert_file);
        return -1;
    }
    if (!file_readable(cfg->key_file)) {
        fprintf(stderr, "config: key_file not readable: %s\n", cfg->key_file);
        return -1;
    }
    if (!file_readable(cfg->ca_file)) {
        fprintf(stderr, "config: ca_file not readable: %s\n", cfg->ca_file);
        return -1;
    }
    if (!valid_log_level(cfg->log_level)) {
        fprintf(stderr, "config: invalid log_level '%s' (use: debug, info, warn, error)\n", cfg->log_level);
        return -1;
    }
    return 0;
}

int config_validate_client(const otpe_client_config_t* cfg) {
    if (!cfg) return -1;
    if (cfg->server_ip[0] == '\0') {
        fprintf(stderr, "config: server_ip is empty\n");
        return -1;
    }
    if (cfg->sni[0] == '\0') {
        fprintf(stderr, "config: sni is empty\n");
        return -1;
    }
    if (cfg->socks_port == cfg->http_port) {
        fprintf(stderr, "config: socks_port and http_port are equal (%u)\n", cfg->socks_port);
        return -1;
    }
    if (cfg->max_udp_sessions < 1) {
        fprintf(stderr, "config: max_udp_sessions must be at least 1\n");
        return -1;
    }
    if (validate_token_hex(cfg->token) != 0) {
        fprintf(stderr, "config: token must be at least %d hex chars\n", OTPE_TOKEN_SIZE * 2);
        return -1;
    }
    if (!file_readable(cfg->ca_file)) {
        fprintf(stderr, "config: ca_file not readable: %s\n", cfg->ca_file);
        return -1;
    }
    if (!file_readable(cfg->client_cert_file)) {
        fprintf(stderr, "config: client_cert_file not readable: %s\n", cfg->client_cert_file);
        return -1;
    }
    if (!file_readable(cfg->client_key_file)) {
        fprintf(stderr, "config: client_key_file not readable: %s\n", cfg->client_key_file);
        return -1;
    }
    if (!valid_log_level(cfg->log_level)) {
        fprintf(stderr, "config: invalid log_level '%s' (use: debug, info, warn, error)\n", cfg->log_level);
        return -1;
    }
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
        } else {
            return -1;
        }
    }
    if (j != out_size) return -1;
    return (int)j;
}