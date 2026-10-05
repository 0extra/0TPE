#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    snprintf(u.host, sizeof(u.host), "%s", ccfg.server_ip);
    u.port = ccfg.server_port;
    snprintf(u.sni, sizeof(u.sni), "%s", ccfg.sni);
    snprintf(u.name, sizeof(u.name), "%s", name);

    char buf[URI_MAX];
    if (uri_generate(&u, buf, sizeof(buf)) < 0) {
        fprintf(stderr, "failed to generate link\n");
        return 1;
    }
    printf("%s\n", buf);
    return 0;
}