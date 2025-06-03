/*
 *  unit.c - general utilites for unit testing
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
#include <stdarg.h>
#include <stdio.h>
 
void slog(int priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
		vprintf(format, ap);
	va_end(ap);
}

int test_stat = 0;
void expect(int check,const char *res) {
    if(check) {
        printf("PASS: %s\n",res);
    }
    else {
        printf("FAIL: %s\n",res);
        test_stat = -1;
    }
}