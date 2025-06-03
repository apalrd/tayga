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
#include <stdio.h>

/* Create gcfg struct */
struct config gcfg;
extern int test_stat;
void expect(int check,const char *res);

/* Example map4 table */
static struct map_entry map4s[4] = {
/* addr6, addr4, type, prefix_len4, prefix_len6, line, dyn.offset */
    { {{{0}}}, {0x09090909}, MAP_TYPE_DYNAMIC, 32, 128, 1, {{0}}},
    { {{{1}}}, {0x00a0b0c}, MAP_TYPE_DYNAMIC, 24, 120, 1, {{0}}},
    { {{{2}}}, {0x00004269}, MAP_TYPE_DYNAMIC, 20, 116, 1, {{0}}},
    { {{{3}}}, {3}, MAP_TYPE_DYNAMIC, 16, 112, 1, {{0}}},
};


static struct map_entry map6s[4] = {
    /* addr6, addr4, type, prefix_len4, prefix_len6, line, dyn.offset */
        { {{{0}}}, {0}, MAP_TYPE_DYNAMIC, 32, 128, 1, {{0}}},
        { {{{0}}}, {0}, MAP_TYPE_DYNAMIC, 24, 120, 1, {{0}}},
        { {{{0}}}, {0}, MAP_TYPE_DYNAMIC, 20, 116, 1, {{0}}},
        { {{{0}}}, {0}, MAP_TYPE_DYNAMIC, 16, 112, 1, {{0}}},
};

/* Fake search function */
struct map_entry *map_search6(struct in6_addr a) {
    if(a.s6_addr32[0] < 4) return &map6s[a.s6_addr32[0]];
    return NULL;
}


int main(int argc, char **argv) {
    char addrbuf[64];
    char addrbuf2[64];
    gcfg.map_entry_len = 4;
    gcfg.map4 = &map4s[0];
    gcfg.map6 = &map6s[0];

    /* Init dynamic mapping tables */
    dyn_init();

    /* Dyn offsets were initialized correctly for this test data */
    expect(gcfg.map4[0].dyn.offset == 0,"Dyn Offset4 0");
    expect(gcfg.map4[1].dyn.offset == 1,"Dyn Offset4 1");
    expect(gcfg.map4[2].dyn.offset == 256+1,"Dyn Offset4 2");
    expect(gcfg.map4[3].dyn.offset == 256+4096+1,"Dyn Offset4 3");
    expect(gcfg.map6[0].dyn.offset == 0,"Dyn Offset6 0");
    expect(gcfg.map6[1].dyn.offset == 1,"Dyn Offset6 1");
    expect(gcfg.map6[2].dyn.offset == 256+1,"Dyn Offset6 2");
    expect(gcfg.map6[3].dyn.offset == 256+4096+1,"Dyn Offset6 3");

    printf("%s: Overall Test Status\n",(test_stat ? "FAIL" : "PASS"));

    /* Test state */
    return test_stat;
}