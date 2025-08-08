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
#include <setjmp.h>
#include <string.h>
#include <time.h>

/* Global vars */
time_t now;

/* Overall test status (1 on failure, 0 on pass) */
int test_stat = 0;
int print_fail_only = 0;

/* Capture slog to the output */
int has_slogged = 0;
int print_slog = 0;
void slog(int priority, const char *format, ...)
{
    //Observe that slog was called
    has_slogged++;
    //Optionally, print it to the log
    if(print_slog) {
        va_list ap;

        va_start(ap, format);
            vprintf(format, ap);
        va_end(ap);
    }
}

/* Capture exit events */
void _exit(int status);
void exit(int status) {
    /* oh no, bad things have happened here */
    printf("FAIL: UNEXPECTED CALL TO EXIT\n");
    _exit(1);
}

/* Expect for long ints */
void expectl(long a, long b, const char *res) {
    if(a != b) {
        printf("FAIL: %s (%ld != %ld)\n",res,a,b);
        test_stat = 1;
    } else {
        if(!print_fail_only) printf("PASS: %s\n",res);
    }
}

/* Expect for strings */
void expects(const char * a, const char * b, int n, const char * res) {
    if(a == NULL && b == NULL) {
        /* Both strings are null */
        if(!print_fail_only) printf("PASS: %s (both null)\n",res);
    } else if(a == NULL) {
        /* Only one string is null */
        printf("FAIL: %s (a null)\n",res);
        test_stat = 1;
    } else if(b == NULL) {
        /* Only one string is null */
        printf("FAIL: %s (b null)\n",res);
        test_stat = 1;
    } else if(a[0] == 0 && b[0] == 0) {
        /* Both are empty */
        if(!print_fail_only) printf("PASS: %s (both empty)\n",res);
    } else if(strncmp(a,b,n)) {
        /* Both do not compare to each other */
        printf("FAIL: %s (%s != %s)\n",res,a,b);
        test_stat = 1;
    } else if(!print_fail_only) printf("PASS: %s (both equal)\n",res);
}

/* Generic expect for booleans */
void expect(int check,const char *res) {
    if(check) {
        if(!print_fail_only) printf("PASS: %s\n",res);
    }
    else {
        printf("FAIL: %s\n",res);
        test_stat = -1;
    }
}

/* Final test status */
int overall() {
    if(test_stat) {
        printf("OVERALL FAIL\n");
        return 1;
    }
    printf("OVERALL PASS\n");
    return 0;
}
