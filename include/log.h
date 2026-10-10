#ifndef OTPE_LOG_H
#define OTPE_LOG_H

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3
} log_level_t;

void        log_set_level(log_level_t level);
log_level_t log_get_level(void);
int         log_level_from_string(const char* s);
const char* log_level_to_string(log_level_t level);

void log_msg(log_level_t level, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define log_debug(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define log_info(...)  log_msg(LOG_INFO,  __VA_ARGS__)
#define log_warn(...)  log_msg(LOG_WARN,  __VA_ARGS__)
#define log_error(...) log_msg(LOG_ERROR, __VA_ARGS__)

#endif