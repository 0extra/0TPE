#include "uri.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void token_to_hex(const uint8_t* token, char* out) {
    for (int i = 0; i < OTPE_TOKEN_SIZE; i++)
        sprintf(out + i * 2, "%02x", token[i]);
    out[OTPE_TOKEN_SIZE * 2] = '\0';
}

static int hex_to_token(const char* hex, uint8_t* token) {
    size_t len = strlen(hex);
    if (len != (size_t)(OTPE_TOKEN_SIZE * 2)) return -1;
    for (int i = 0; i < OTPE_TOKEN_SIZE; i++) {
        int hi = hexval(hex[i * 2]);
        int lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        token[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int uri_parse(const char* uri, otpe_uri_t* out) {
    memset(out, 0, sizeof(*out));

    if (strncmp(uri, "otpe://", 7) != 0) return -1;
    const char* p = uri + 7;

    const char* at = strchr(p, '@');
    if (!at) return -1;

    char token_hex[32];
    size_t token_len = (size_t)(at - p);
    if (token_len >= sizeof(token_hex)) return -1;
    memcpy(token_hex, p, token_len);
    token_hex[token_len] = '\0';
    if (hex_to_token(token_hex, out->token) != 0) return -1;

    p = at + 1;
    const char* colon = strchr(p, ':');
    if (!colon) return -1;

    size_t host_len = (size_t)(colon - p);
    if (host_len == 0 || host_len >= sizeof(out->host)) return -1;
    memcpy(out->host, p, host_len);
    out->host[host_len] = '\0';

    p = colon + 1;
    const char* q = strchr(p, '?');
    const char* hash = strchr(p, '#');
    const char* end_port = q ? q : (hash ? hash : p + strlen(p));

    char port_str[8];
    size_t port_len = (size_t)(end_port - p);
    if (port_len == 0 || port_len >= sizeof(port_str)) return -1;
    memcpy(port_str, p, port_len);
    port_str[port_len] = '\0';
    out->port = (uint16_t)atoi(port_str);
    if (out->port == 0) return -1;

    out->sni[0] = '\0';
    out->name[0] = '\0';

    if (q) {
        const char* end_q = hash ? hash : q + strlen(q);
        const char* sni_pos = strstr(q, "sni=");
        if (sni_pos && sni_pos < end_q) {
            sni_pos += 4;
            size_t sl = (size_t)(end_q - sni_pos);
            if (sl >= sizeof(out->sni)) sl = sizeof(out->sni) - 1;
            memcpy(out->sni, sni_pos, sl);
            out->sni[sl] = '\0';
        }
    }

    if (hash) {
        size_t nl = strlen(hash + 1);
        if (nl >= sizeof(out->name)) nl = sizeof(out->name) - 1;
        memcpy(out->name, hash + 1, nl);
        out->name[nl] = '\0';
    }

    return 0;
}

int uri_generate(const otpe_uri_t* cfg, char* buffer, size_t buffer_size) {
    char hex[32];
    token_to_hex(cfg->token, hex);

    int written = snprintf(buffer, buffer_size,
        "otpe://%s@%s:%u?sni=%s#%s",
        hex,
        cfg->host,
        cfg->port,
        cfg->sni[0] ? cfg->sni : "www.microsoft.com",
        cfg->name[0] ? cfg->name : "0TPE_Server");

    if (written < 0 || (size_t)written >= buffer_size) return -1;
    return written;
}