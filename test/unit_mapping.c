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

void dump_maps() {
    char addrbuf[64];
    char addrbuf2[64];
    /* Dump map data */
    printf("Map State: Len %d Size %d\n",gcfg.map_entry_len,gcfg.map_entry_size);
    for(int i = 0; i < gcfg.map_entry_size; i++) {
        printf("Map4 Entry %d\n",i);		
        printf("Entry %s/%d type %d\n",
			inet_ntop(AF_INET,&gcfg.map4[i].addr4,addrbuf,64),
			gcfg.map4[i].prefix_len4,gcfg.map4[i].type);
    }    
    for(int i = 0; i < gcfg.map_entry_size; i++) {
        printf("Map6 Entry %d\n",i);		
        printf("Entry %s/%d type %d\n",
			inet_ntop(AF_INET6,&gcfg.map6[i].addr6,addrbuf,64),
			gcfg.map6[i].prefix_len6,gcfg.map6[i].type);
    }
}


int main(int argc, char **argv) {

    printf("Starting unit test for mapping.c\n");

    /* Call init function and verify no errors (it will exit on error) */
    map_init();

    /* Call mapping function with a bunch of invalid cases */
    expect(map_insert(NULL),"Null Map");
    struct map_entry uut = {0};
    uut.prefix_len4 = -1;
    expect(map_insert(&uut),"Negaitve len4");
    uut.prefix_len4 = 33;
    expect(map_insert(&uut),"Invalid len4");
    uut.prefix_len4 = 16;
    uut.prefix_len6 = -1;
    expect(map_insert(&uut),"Negaitve len6");
    uut.prefix_len6 = 129;
    expect(map_insert(&uut),"Invalid len6");

    /* Insert an entry at the beginning */
    uut.addr4.s_addr = 0;
    uut.prefix_len4 = 1;
    uut.addr6.s6_addr32[0] = htonl(0x0064ff9b);
    uut.prefix_len6 = 96;
    uut.type = MAP_TYPE_RFC6052;
    uut.line = 1;
    expect(!map_insert(&uut),"Insert Default Map");

    
    /* Insert an entry earlier in v4 and v6 space */
    uut.addr4.s_addr = htonl(0x09090900);
    uut.prefix_len4 = 24;
    uut.addr6.s6_addr32[0] = htonl(0x20010db8);
    uut.addr6.s6_addr32[3] = htonl(0x6900);
    uut.prefix_len6 = 120;
    uut.type = MAP_TYPE_STATIC;
    uut.line = 2;
    expect(!map_insert(&uut),"Insert Medium Map");
    
    /* Insert an entry even earlier in v4 and v6 space */
    uut.addr4.s_addr = htonl(0x09090a01);
    uut.prefix_len4 = 32;
    uut.addr6.s6_addr32[0] = htonl(0x20010db8);
    uut.addr6.s6_addr32[3] = htonl(0x420);
    uut.prefix_len6 = 128;
    uut.type = MAP_TYPE_STATIC;
    uut.line = 3;
    expect(!map_insert(&uut),"Insert Early Map");

    /* Insert an entry in the middle for v4 and end in v6 */
    uut.addr4.s_addr = htonl(0x0a000000);
    uut.prefix_len4 = 16;
    uut.addr6.s6_addr32[0] = htonl(0x20010db8);
    uut.addr6.s6_addr32[3] = 0;
    uut.prefix_len6 = 48;
    uut.type = MAP_TYPE_DYNAMIC;
    uut.line = 4;
    expect(!map_insert(&uut),"Insert Different V4/V6 Map");

    
    /* Insert a very long prefix */
    uut.addr4.s_addr = htonl(0x0c000000);
    uut.prefix_len4 = 8;
    uut.addr6.s6_addr32[0] = htonl(0x3fff0000);
    uut.addr6.s6_addr32[3] = 0;
    uut.prefix_len6 = 16;
    uut.type = MAP_TYPE_DYNAMIC;
    uut.line = 5;
    expect(!map_insert(&uut),"Insert Very Short Prefix");
    
    /* Another prefix we need later */
    uut.addr4.s_addr = htonl(0x0d000000);
    uut.prefix_len4 = 8;
    uut.addr6.s6_addr32[0] = htonl(0x3fffabcd);
    uut.addr6.s6_addr32[3] = 0;
    uut.prefix_len6 = 32;
    uut.type = MAP_TYPE_DYNAMIC;
    uut.line = 5;
    expect(!map_insert(&uut),"Insert Very Short Prefix 2");

    
    /* Insert so many entries that we need to resize the maps */
    for(int i = 0; i < 24; i++) {
        uut.addr4.s_addr = htonl(0x0b000000 | i);
        uut.prefix_len4 = 32;
        uut.addr6.s6_addr32[0] = htonl(0x20010db8);
        uut.addr6.s6_addr32[3] = htonl(0x64640000 | i);
        uut.prefix_len6 = 128;
        uut.type = MAP_TYPE_STATIC;
        uut.line = 6+i;
        expect(!map_insert(&uut),"Insert A Lot of Maps");
    }

    /* Check results for map4 */
    for(int i = 0; i < 32; i++)
    {
        char testid[64];
        sprintf(testid,"Map4 Entry %d Addr4",i);
        if(i < 1) expect(gcfg.map4[i].addr4.s_addr == htonl(0x09090a01),testid);
        else if(i < 25) expect(gcfg.map4[i].addr4.s_addr == htonl(0x0b000000 | (i - 1)),testid);
        else if(i < 26) expect(gcfg.map4[i].addr4.s_addr == htonl(0x09090900),testid);
        else if(i < 27) expect(gcfg.map4[i].addr4.s_addr == htonl(0x0a000000),testid);
        else if(i < 28) expect(gcfg.map4[i].addr4.s_addr == htonl(0x0c000000),testid);
        else if(i < 29) expect(gcfg.map4[i].addr4.s_addr == htonl(0x0d000000),testid);
        else expect(gcfg.map4[i].addr4.s_addr == htonl(0),testid);
        sprintf(testid,"Map4 Entry %d Type",i);
        if(i < 26) expect(gcfg.map4[i].type == MAP_TYPE_STATIC,testid);
        else if(i < 29) expect(gcfg.map4[i].type == MAP_TYPE_DYNAMIC,testid);
        else if(i < 30) expect(gcfg.map4[i].type == MAP_TYPE_RFC6052,testid);
        else expect(gcfg.map4[i].type == MAP_TYPE_INVALID,testid);
    }
    /* Check results for map6 */    
    for(int i = 0; i < 32; i++)
    {
        char testid[64];
        sprintf(testid,"Map6 Entry %d Addr4",i);
        struct in6_addr ip6 = {0};
        if(i < 26) ip6.s6_addr32[0] = htonl(0x20010db8);
        else if(i < 27) ip6.s6_addr32[0] = htonl(0x64ff9b);
        else if(i < 28) ip6.s6_addr32[0] = htonl(0x20010db8);
        else if(i < 29) ip6.s6_addr32[0] = htonl(0x3fffabcd);
        else if(i < 30) ip6.s6_addr32[0] = htonl(0x3fff0000);
        if(i < 1) ip6.s6_addr32[3] = htonl(0x420);
        else if(i < 25) ip6.s6_addr32[3] = htonl(0x64640000 | (i - 1));
        else if(i < 26) ip6.s6_addr32[3] = htonl(0x6900);
        expect(IN6_ARE_ADDR_EQUAL(&gcfg.map6[i].addr6,&ip6),testid);
        sprintf(testid,"Map6 Entry %d Type",i);
        if(i < 26) expect(gcfg.map6[i].type == MAP_TYPE_STATIC,testid);
        else if(i < 27) expect(gcfg.map6[i].type == MAP_TYPE_RFC6052,testid);
        else if(i < 30) expect(gcfg.map6[i].type == MAP_TYPE_DYNAMIC,testid);
        else expect(gcfg.map6[i].type == MAP_TYPE_INVALID,testid);
    }
    dump_maps();

    /* Now test cases for search4 */
    struct in_addr test4;
    test4.s_addr = htonl(0x0b00000c);
    expect(map_search4(test4) == &gcfg.map4[13],"Search4 /32");
    test4.s_addr = htonl(0x0909090a);
    expect(map_search4(test4) == &gcfg.map4[25],"Search4 /24");
    test4.s_addr = htonl(0x0a006942);
    expect(map_search4(test4) == &gcfg.map4[26],"Search4 /16");
    test4.s_addr = htonl(0x01020304);
    expect(map_search4(test4) == &gcfg.map4[29],"Search4 /1");
    test4.s_addr = htonl(0x81020304);
    expect(map_search4(test4) == NULL,"Search4 Default");

    struct in6_addr test6;
    test6.s6_addr32[0] = htonl(0x3fff1234);
    expect(map_search6(test6) == &gcfg.map6[29],"Search6 /16");
    test6.s6_addr32[0] = htonl(0x3fffabcd);
    expect(map_search6(test6) == &gcfg.map6[28],"Search6 /32");
    test6.s6_addr32[0] = htonl(0x20010db8);
    test6.s6_addr32[1] = htonl(0x00006940);
    expect(map_search6(test6) == &gcfg.map6[27],"Search6 /48");
    test6.s6_addr32[0] = htonl(0x0064ff9b);
    test6.s6_addr32[1] = 0;
    expect(map_search6(test6) == &gcfg.map6[26],"Search6 /96");
    test6.s6_addr32[0] = htonl(0x20010db8);
    test6.s6_addr32[3] = htonl(0x00006901);
    expect(map_search6(test6) == &gcfg.map6[25],"Search6 /126");
    test6.s6_addr32[0] = htonl(0x20010db8);
    test6.s6_addr32[3] = htonl(0x64640003);
    expect(map_search6(test6) == &gcfg.map6[4],"Search6 /128");

    printf("%s: Overall Test Status\n",(test_stat ? "FAIL" : "PASS"));

    /* Test state */
    return test_stat;
}