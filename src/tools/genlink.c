#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "uri.h"
#include "config.h"

static void usage(const char* prog) {
    printf("Usage: %s [config_file] [name]\n", prog);
    printf("  config_file  path to 0tpe.conf (default: 0tpe.conf)\n");
    printf("  name         server name to embed in link (default: 0TPE_Server)\n");
}

int main(int argc, char** argv) {
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }

    const char* cfg_path = argc > 1 ? argv[1] : "0tpe.conf";
    const char* name = argc > 2 ? argv[2] : "0TPE_Server";

    otpe_client_config_t ccfg;
    if (config_load_client(cfg_path, &ccfg) != 0) {
        fprintf(stderr, "Warning: %s not found, using defaults\n", cfg_path);
    }

    otpe_uri_t u;
    memset(&u, 0, sizeof(u));
    config_token_to_bytes(ccfg.token, u.token, OTPE_TOKEN_SIZE);
    strncpy(u.host, ccfg.server_ip, sizeof(u.host) - 1);
    u.port = ccfg.server_port;
    strncpy(u.sni, ccfg.sni, sizeof(u.sni) - 1);
    strncpy(u.name, name, sizeof(u.name) - 1);

    char buf[URI_MAX];
    if (uri_generate(&u, buf, sizeof(buf)) < 0) {
        fprintf(stderr, "failed to generate link\n");
        return 1;
    }
    printf("%s\n", buf);
    return 0;
}