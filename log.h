#ifndef __TAYGA_LOG_H__
#define __TAYGA_LOG_H__

#include <stdarg.h>

#define STRINGIFY_IMPL(x) #x
#define STRINGIFY(x) STRINGIFY_IMPL(x)
#define slog(prio, ...) slog_impl(prio, "CODE_FILE=" __FILE__, "CODE_LINE=" STRINGIFY(__LINE__), __func__, __VA_ARGS__)

void slog_impl(int priority, const char *file, const char *line, const char *func, const char *format, ...);

int log_init(void);
int log_notify_ready(void);
void log_cleanup(void);

#endif
