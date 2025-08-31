/*
 *  unit.h - general utilites for unit testing
 *
 *  part of TAYGA <https://github.com/apalrd/tayga>
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

/* Overall test status (1 on failure, 0 on pass) */
extern int test_stat;
extern int print_fail_only;

/* Capture slog to the output */
extern int has_slogged;
extern int print_slog;
void slog(int priority, const char *format, ...);
/* Expect for long ints */
void expectl(long a, long b, const char *res);
/* Expect for strings */
void expects(const char * a, const char * b, int n, const char * res);
/* Generic expect for booleans */
void expect(int check,const char *res);
/* Overall test status */
int overall();
