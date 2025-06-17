/*
 *  unit_mapping.c - unit test for mapping.c
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
#include "tayga.h"
#include <stdarg.h>

/* Create gcfg struct */
struct config gcfg;
extern int test_stat;
void expect(int check,const char *res);



int main(int argc, char **argv) {

    printf("Starting unit test for mapping.c\n");


    printf("%s: Overall Test Status\n",(test_stat ? "FAIL" : "PASS"));

    /* Test state */
    return test_stat;
}