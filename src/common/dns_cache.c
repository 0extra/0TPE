#include "dns_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#define DNS_CACHE_SIZE 256
#define DNS_CACHE_TTL 30

typedef struct {
    char host[256];
    uint16_t port;
    int socktype;
    struct addrinfo* res;
    time_t expire_at;
    int in_use;
} dns_entry_t;

static dns_entry_t g_cache[DNS_CACHE_SIZE];
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_gai_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t g_next_slot = 0;

void dns_cache_init(void) {
    pthread_mutex_lock(&g_cache_lock);
    memset(g_cache, 0, sizeof(g_cache));
    g_next_slot = 0;
    pthread_mutex_unlock(&g_cache_lock);
}

static struct addrinfo* cache_find_locked(const char* host, uint16_t port, int socktype) {
    time_t now = time(NULL);
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_cache[i].in_use) continue;
        if (g_cache[i].expire_at < now) continue;
        if (g_cache[i].port != port) continue;
        if (g_cache[i].socktype != socktype) continue;
        if (strcmp(g_cache[i].host, host) != 0) continue;
        return g_cache[i].res;
    }
    return NULL;
}

static void cache_insert_locked(const char* host, uint16_t port, int socktype,
                                struct addrinfo* res, time_t now) {
    int slot = -1;
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_cache[i].in_use) { slot = i; break; }
    }
    if (slot < 0) {
        slot = (int)g_next_slot;
        g_next_slot = (g_next_slot + 1) % DNS_CACHE_SIZE;
        if (g_cache[slot].res) freeaddrinfo(g_cache[slot].res);
    }
    strncpy(g_cache[slot].host, host, sizeof(g_cache[slot].host) - 1);
    g_cache[slot].host[sizeof(g_cache[slot].host) - 1] = '\0';
    g_cache[slot].port = port;
    g_cache[slot].socktype = socktype;
    g_cache[slot].res = res;
    g_cache[slot].expire_at = now + DNS_CACHE_TTL;
    g_cache[slot].in_use = 1;
}

struct addrinfo* dns_cache_lookup(const char* host, uint16_t port, int socktype) {
    struct addrinfo* res;

    pthread_mutex_lock(&g_cache_lock);
    res = cache_find_locked(host, port, socktype);
    pthread_mutex_unlock(&g_cache_lock);
    if (res) return res;

    pthread_mutex_lock(&g_gai_lock);

    pthread_mutex_lock(&g_cache_lock);
    res = cache_find_locked(host, port, socktype);
    pthread_mutex_unlock(&g_cache_lock);
    if (res) {
        pthread_mutex_unlock(&g_gai_lock);
        return res;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo* fresh = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &fresh);
    if (rc != 0) {
        pthread_mutex_unlock(&g_gai_lock);
        return NULL;
    }

    time_t now = time(NULL);
    pthread_mutex_lock(&g_cache_lock);
    cache_insert_locked(host, port, socktype, fresh, now);
    pthread_mutex_unlock(&g_cache_lock);

    pthread_mutex_unlock(&g_gai_lock);
    return fresh;
}