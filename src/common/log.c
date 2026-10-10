#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>

static log_level_t g_level = LOG_INFO;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void log_set_level(log_level_t level) {
    g_level = level;
}

log_level_t log_get_level(void) {
    return g_level;
}

int log_level_from_string(const char* s) {
    if (!s) return -1;
    if (strcmp(s, "debug") == 0) return LOG_DEBUG;
    if (strcmp(s, "info")  == 0) return LOG_INFO;
    if (strcmp(s, "warn")  == 0) return LOG_WARN;
    if (strcmp(s, "error") == 0) return LOG_ERROR;
    return -1;
}

const char* log_level_to_string(log_level_t level) {
    switch (level) {
        case LOG_DEBUG: return "debug";
        case LOG_INFO:  return "info";
        case LOG_WARN:  return "warn";
        case LOG_ERROR: return "error";
    }
    return "?";
}

static const char* level_tag(log_level_t level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
    }
    return "?";
}

void log_msg(log_level_t level, const char* fmt, ...) {
    if (level < g_level) return;

    pthread_mutex_lock(&g_lock);
    fprintf(stderr, "[%s] ", level_tag(level));
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
    pthread_mutex_unlock(&g_lock);
}