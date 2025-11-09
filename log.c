/*
 *  log.c - logging related functions
 *
 *  part of TAYGA <https://github.com/apalrd/tayga>
 *  Copyright (C) 2010  Nathan Lutchansky <lutchann@litech.org>
 *  Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */


#include "tayga.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>


/* Log the message to the configured logger */
void slog_impl(int priority, const char *file, const char *line, const char *func, const char *format, ...)
{
	va_list ap;
	(void)file;
	(void)line;
	(void)func;

	va_start(ap, format);
	switch (gcfg->log_out) {
        default:
		case LOG_TO_STDOUT:
			vprintf(format, ap);
			break;
		case LOG_TO_SYSLOG:
			vsyslog(priority, format, ap);
			break;
		case LOG_TO_JOURNAL:
			journal_printv_with_location(priority, file, line, func, format, ap);
			break;
	}
	va_end(ap);
}


union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_un sun;
};

/* The following is adapted from
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 *
 * SPDX-License-Identifier: MIT-0
 *
 * Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */
int notify(const char *message) {
    union sockaddr_union socket_addr = {
        .sun.sun_family = AF_UNIX,
    };
    size_t path_length, message_length;
    const char *socket_path;

    /* Verify the argument first */
    if (!message)
        return -EINVAL;

    message_length = strlen(message);
    if (message_length == 0)
        return -EINVAL;

    /* If the variable is not set, the protocol is a noop */
    socket_path = getenv("NOTIFY_SOCKET");
    if (!socket_path)
        return 0; /* Not set? Nothing to do */

    /* Only AF_UNIX is supported, with path or abstract sockets */
    if (socket_path[0] != '/' && socket_path[0] != '@')
        return -EAFNOSUPPORT;

    path_length = strlen(socket_path);
    /* Ensure there is room for NUL byte */
    if (path_length >= sizeof(socket_addr.sun.sun_path))
        return -E2BIG;

    memcpy(socket_addr.sun.sun_path, socket_path, path_length);

    /* Support for abstract socket */
    if (socket_addr.sun.sun_path[0] == '@')
        socket_addr.sun.sun_path[0] = 0;

    int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    if (connect(fd, &socket_addr.sa, offsetof(struct sockaddr_un, sun_path) + path_length) != 0) {
        close(fd);
        return -errno;
    }

    ssize_t written = write(fd, message, message_length);
    if (written != (ssize_t) message_length) {
        int ret = written < 0 ? -errno : -EPROTO;
        close(fd);
        return ret;
    }

    close(fd);
    return 1; /* Notified! */
}


/* Simplified journal implementation
 * We assume that the message is always <2048 bytes and has no internal newlines
 * This also is not thread-safe
 *
 * https://systemd.io/JOURNAL_NATIVE_PROTOCOL/
 */

#define JOURNAL_SOCKET "/run/systemd/journal/socket"
#define SNDBUF_SIZE (8 * 1024 * 1024)
#define MESSAGE_SIZE 2048

static int journal_fd = -1;
static const char *syslog_identifier = NULL;

/* Open the systemd journal. Not threadsafe. */
int journal_init(const char *ident) {
    if (journal_fd >= 0)
        return 0;

    if (ident == NULL)
        return -EINVAL;

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    int value = SNDBUF_SIZE;
    int r = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof value);
    if (r < 0)
        return r;

    journal_fd = fd;
    syslog_identifier = ident;
    return 0;
}

/* Close the systemd journal. Not threadsafe. */
void journal_cleanup(void) {
    close(journal_fd);
    journal_fd = -1;
}

/* Send a message to the systemd journal.
 * Preconditions:
 *   0 <= priority <= 7
 *   file =~ ^CODE_FILE=[^\n]+$
 *   line =~ ^CODE_LINE=[^\n]+$
 *   func =~ ^[^\n]+$
 *   format =~ ^[^\n]+\n?$
 *   vsnprintf(NULL, 0, format, ap) < MESSAGE_SIZE
 */
int journal_printv_with_location(
        int priority, const char *file, const char *line, const char *func,
        const char *format, va_list ap)
{
    char pri[11] = "PRIORITY=0\n";
    char msg[8 + MESSAGE_SIZE] = "MESSAGE=";
    struct iovec iov[10];
    size_t iovlen = 10;

    if (priority < 0 || priority > 7 ||
            file == NULL || line == NULL || func == NULL || format == NULL)
        return -EINVAL;

    pri[9] += priority;

    int len = vsnprintf(msg + 8, sizeof(msg) - 8, format, ap);
    if (len >= MESSAGE_SIZE)
        return -E2BIG;

    char *msg_end = strchr(msg, '\n');
    if (msg_end == NULL) {
        /* No newline: replace null byte with newline
         * Safety: len < MESSAGE_SIZE, so len + 8 < 8 + MESSAGE_SIZE */
        msg[len + 8] = '\n';
        len++;
    } else {
        /* Truncate the message at the first newline */
        len = msg_end - &msg[8] + 1;
    }

    /* MESSAGE= */
    iov[0].iov_base = msg;
    iov[0].iov_len = len + 8;
    /* PRIORITY= */
    iov[1].iov_base = pri;
    iov[1].iov_len = sizeof pri;
    /* CODE_FILE= */
    iov[2].iov_base = (char *)file;
    iov[2].iov_len = strlen(file);
    iov[3].iov_base = "\n";
    iov[3].iov_len = 1;
    /* CODE_LINE= */
    iov[4].iov_base = (char *)line;
    iov[4].iov_len = strlen(line);
    /* CODE_FUNC= */
    iov[5].iov_base = "\nCODE_FUNC=";
    iov[5].iov_len = strlen("\nCODE_FUNC=");
    iov[6].iov_base = (char *)func;
    iov[6].iov_len = strlen(func);
    /* SYSLOG_IDENTIFIER= */
    iov[7].iov_base = "\nSYSLOG_IDENTIFIER=";
    iov[7].iov_len = strlen("\nSYSLOG_IDENTIFIER=");
    iov[8].iov_base = (char *)syslog_identifier;
    iov[8].iov_len = strlen(syslog_identifier);
    iov[9].iov_base = "\n";
    iov[9].iov_len = 1;

    static const union sockaddr_union sa = {
        .sun.sun_family = AF_UNIX,
        .sun.sun_path = JOURNAL_SOCKET,
    };

    struct msghdr mh = {0};
    mh.msg_name = (void *)&sa.sa;
    mh.msg_namelen = offsetof(struct sockaddr_un, sun_path) + strlen(JOURNAL_SOCKET) + 1;
    mh.msg_iov = iov;
    mh.msg_iovlen = iovlen;

    int r = sendmsg(journal_fd, &mh, MSG_NOSIGNAL);
    if (r >= 0)
        return 0;

    return -errno;
}
