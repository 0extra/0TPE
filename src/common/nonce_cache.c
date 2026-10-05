#include "nonce_cache.h"
#include <string.h>
#include <pthread.h>
#include <time.h>

#define CACHE_SIZE 4096
#define MAX_AGE_SECONDS 60

typedef struct {
    uint8_t  nonce[32];
    size_t   nonce_len;
    uint64_t timestamp;
    int      used;
} cache_entry_t;

static cache_entry_t   g_cache[CACHE_SIZE];
static size_t          g_next_slot = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void nonce_cache_init(void) {
    pthread_mutex_lock(&g_lock);
    memset(g_cache, 0, sizeof(g_cache));
    g_next_slot = 0;
    pthread_mutex_unlock(&g_lock);
}

int nonce_cache_check_and_add(const uint8_t* nonce, size_t nonce_len, uint64_t timestamp) {
    if (nonce_len == 0 || nonce_len > 32) return -1;

    uint64_t now = (uint64_t)time(NULL);
    uint64_t oldest = (now > MAX_AGE_SECONDS) ? (now - MAX_AGE_SECONDS) : 0;

    pthread_mutex_lock(&g_lock);

    for (size_t i = 0; i < CACHE_SIZE; i++) {
        if (!g_cache[i].used) continue;
        if (g_cache[i].timestamp < oldest) continue;
        if (g_cache[i].nonce_len != nonce_len) continue;
        if (memcmp(g_cache[i].nonce, nonce, nonce_len) == 0) {
            pthread_mutex_unlock(&g_lock);
            return 1;
        }
    }

    cache_entry_t* slot = &g_cache[g_next_slot];
    memcpy(slot->nonce, nonce, nonce_len);
    slot->nonce_len = nonce_len;
    slot->timestamp = timestamp;
    slot->used = 1;
    g_next_slot = (g_next_slot + 1) % CACHE_SIZE;

    pthread_mutex_unlock(&g_lock);
    return 0;
}