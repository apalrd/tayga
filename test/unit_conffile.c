/*
 *  unit_conffile.c - Unit test for conffile.c
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

#include "test/unit.h"
#include "tayga.h"

/* Test copy of gcfg */
static struct config tcfg;

/* Map4/Map6 lists as strings */
static char *tmap4[100] = {0};
static char *tmap6[100] = {0};


/* Function to simulate getenv 
 * set getenv_case to a nonzero number to change the return
 * Then verify that it is zero and has been read
 */
static int getenv_case = 0;
char * getenv(const char * var) {
    if(strcmp(var,"STATE_DIRECTORY")) return NULL;
    int temp = getenv_case;
    getenv_case = 0;
    switch(temp) {
    case 1: /* Correct value */
        return "/var/lib/tayga";
    case 2: /* relative path */
        return "var/lib/tayga";
    case 3: /* way too long */
        return  "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var"
        "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var"
        "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var"
        "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var"
        "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var"
        "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var"
        "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var"
        "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var"
        "/var/var/var/var/var/var/var/var/var/var/var/var/var/var/var";
    case 4: /* Multiple directories */
        return "/var/lib/tayga:/var/db/tayga";
    default:
        expect(0,"Unknown Getenv Call");
        return NULL;
    }

}

/* Function to compare tcfg to gcfg */
void test_config_compare(void) {
    /* Check pointer */
    expect(gcfg != NULL,"GCFG is not null");
    if(!gcfg) return;

    /* Compare every field in the struct */
    expects(gcfg->tundev, tcfg.tundev, IFNAMSIZ, "tundev");
    expects(gcfg->data_dir, tcfg.data_dir, 512, "data_dir");
    expectl(gcfg->recv_buf_size, tcfg.recv_buf_size, "recv_buf_size");
    expectl(gcfg->local_addr4.s_addr, tcfg.local_addr4.s_addr, "local_addr4");
    expectl(gcfg->local_addr6.s6_addr32[0],tcfg.local_addr6.s6_addr32[0], "local_addr6[0]");
    expectl(gcfg->local_addr6.s6_addr32[1],tcfg.local_addr6.s6_addr32[1], "local_addr6[1]");
    expectl(gcfg->local_addr6.s6_addr32[2],tcfg.local_addr6.s6_addr32[2], "local_addr6[2]");
    expectl(gcfg->local_addr6.s6_addr32[3],tcfg.local_addr6.s6_addr32[3], "local_addr6[3]");
    expectl(gcfg->dyn_min_lease, tcfg.dyn_min_lease, "dyn_min_lease");
    expectl(gcfg->dyn_max_lease, tcfg.dyn_max_lease, "dyn_max_lease");
    expectl(gcfg->max_commit_delay, tcfg.max_commit_delay, "max_commit_delay");
    expectl(gcfg->hash_bits,tcfg.hash_bits, "hash_bits");
    expectl(gcfg->cache_size,tcfg.cache_size, "cache_size");
    expectl(gcfg->ipv6_offlink_mtu,tcfg.ipv6_offlink_mtu, "ipv6_offlink_mtu");
    expectl(gcfg->lazy_frag_hdr,tcfg.lazy_frag_hdr, "lazy_frag_hdr");
    expectl(gcfg->mtu,tcfg.mtu, "mtu");
    expectl(gcfg->wkpf_strict, tcfg.wkpf_strict, "wkpf_strict");
    expectl(gcfg->log_opts, tcfg.log_opts, "log_opts");
    expectl(gcfg->udp_cksum_mode, tcfg.udp_cksum_mode, "udp_cksum_mode");

    /* Pointers in gcfg which are not touched by conffile.c */
    expectl(gcfg->urandom_fd, 0, "urandom_fd");
    expectl(gcfg->tun_fd, 0, "tun_fd");
    expectl((long)gcfg->recv_buf, 0, "recv_buf");

    int count = 0, expect_count = 0;
	struct list_head *entry;
    char addrbuf[64], addrbuf2[64];
    char linebuf[512], namebuf[64];
    /* Iterate over map4 list and compare length */
	list_for_each(entry, &gcfg->map4_list) {
        count++;
    }
    for(expect_count = 0; tmap4[expect_count];expect_count++) ;
    expectl(count,expect_count,"map4 length");

    /* If the lengths are equal, compare contents */
    if(count == expect_count) {
        count = 0;
        /* Compare contents of lists as strings */	
        list_for_each(entry, &gcfg->map4_list) {
            struct map4 *s4;
            sprintf(namebuf,"map4[%d]",count);
            s4 = list_entry(entry, struct map4, list);
            sprintf(linebuf,"%s/%d type %d mask %s",
                inet_ntop(AF_INET,&s4->addr,addrbuf,64),
                s4->prefix_len,s4->type,
                inet_ntop(AF_INET,&s4->mask,addrbuf2,64));
            expects(linebuf,tmap4[count],512,namebuf);
            count++;
        }
	}

    /* Iterate over map6 list and compare length */
    count = 0;
	list_for_each(entry, &gcfg->map6_list) {
        count++;
    }
    for(expect_count = 0; tmap6[expect_count];expect_count++) ;
    expectl(count,expect_count,"map6 length");

    /* If the lengths are equal, compare contents */
    if(count == expect_count) {
        count = 0;
        /* Compare contents of lists as strings */	
        list_for_each(entry, &gcfg->map6_list) {
            struct map6 *s6;
            sprintf(namebuf,"map6[%d]",count);
            s6 = list_entry(entry, struct map6, list);
            sprintf(linebuf,"%s/%d type %d mask %s",
                inet_ntop(AF_INET6,&s6->addr,addrbuf,64),
                s6->prefix_len,s6->type,
                inet_ntop(AF_INET6,&s6->mask,addrbuf2,64));
            expects(linebuf,tmap6[count],512,namebuf);
            count++;
        }
	}

    /* Structs */
    //expect(gcfg->map6_list == tcfg.map6_list, "map6_list");
    //expect(gcfg->map4_list == tcfg.map4_list, "map4_list");
    //expect(gcfg->dynamic_pool == tcfg.dynamic_pool, "dynamic_pool");
    //expect(gcfg->hash_table4 == tcfg.hash_table4, "hash_table4");
    //expect(gcfg->hash_table6 == tcfg.hash_table6, "hash_table6");

}

/**
 * @brief Test function config_init
 */
void test_config_init(void) {
    /* Setup gcfg invalid */
    gcfg = NULL;

    /* Call config_init */
    config_init();

    /* Setup expected outputs */
    tcfg.recv_buf_size = 65540;
    tcfg.dyn_min_lease = 7440;
    tcfg.dyn_max_lease = 1209600;
    tcfg.max_commit_delay = 302400;
    tcfg.hash_bits = 7;
    tcfg.cache_size = 1<<13;
    tcfg.lazy_frag_hdr = 1;
    tcfg.wkpf_strict = 1;

    /* Compare to our initialized tcfg */
    printf("TEST CASE: config_init\n");
    test_config_compare();
}

void test_config_read(void) {
    FILE* fd;
    char * conffile;
    char * testcase;

    /* conf file pointer is null */
    printf("TEST CASE: conffile is null\n");
    expect(config_read(NULL),"Failed");

    /* conf file does not exist */
    printf("TEST CASE: conffile does not exist\n");
    expect(config_read("empty.conf"),"Failed");
    

    /* Example config */
    conffile = "tayga.conf.example";
    printf("TEST CASE: example conf file\n");
    free(gcfg);
    config_init();
    expect(!config_read(conffile),"Passed");
    tcfg.wkpf_strict = 0;
    strcpy(tcfg.tundev,"nat64");
    tcfg.local_addr4.s_addr = htonl(0xc0a8ff01);
    /* Two map4 entries */
    tmap4[0] = "192.168.255.0/24 type 2 mask 255.255.255.0";
    tmap4[1] = "0.0.0.0/0 type 1 mask 0.0.0.0";
    tmap4[2] = 0;
    tmap6[0] = "2001:db8:1:ffff::/96 type 1 mask ffff:ffff:ffff:ffff:ffff:ffff::";
    tmap6[1] = 0;
    test_config_compare();
    

    /* Test Case 1 - blank conf file */
    conffile = "unit_conffile.conf";
    printf("TEST CASE: blank conf file\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "#this file is empty\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(!config_read(conffile),"Passed");
    tcfg.data_dir[0] = 0;
    tcfg.tundev[0] = 0;
    tcfg.local_addr4.s_addr = 0;
    tcfg.wkpf_strict = 1;
    tmap4[0] = 0;
    tmap6[0] = 0;
    test_config_compare();

    /* Test Case - duplicate tun devs */
    printf("TEST CASE: duplicate tun dev\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "tun-device nat64\ntun-device clat";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - duplicate ipv4-addr's */
    printf("TEST CASE: duplicate ipv4-addr\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "ipv4-addr 192.168.255.1\nipv4-addr 192.168.255.2\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - ipv4-addr is not a v4-addr */
    printf("TEST CASE: invalid ipv4-addr\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "ipv4-addr hello\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - ipv4-addr is reserved */
    printf("TEST CASE: reserved v4-addr\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "ipv4-addr 127.0.1.1\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - ipv6-addr duplicate */
    printf("TEST CASE: duplicate ipv6-addr\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "ipv6-addr 2001:db8::1\nipv6-addr 2001:db8::2";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - invalid ipv6-addr */
    printf("TEST CASE: invalid ipv6-addr\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "ipv6-addr 2001:db8::hello\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - ipv4-6-addr reserved */
    printf("TEST CASE: reserved ipv6-addr\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "ipv6-addr fe80::1\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - prefix has host bits set */
    printf("TEST CASE: prefix has host bits set\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::6/96\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - prefix reserved */
    printf("TEST CASE: prefix reserved\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix fe80::/96\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - prefix invalid length */
    printf("TEST CASE: prefix invalid length\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/95\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - prefix duplicate */
    printf("TEST CASE: prefix duplicate\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\nprefix 64:ff9b:1::/96";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - wkpf strict not a known string */
    printf("TEST CASE: wkpf invalid\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "wkpf-strict hello\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - udp cksum mode invalid */
    printf("TEST CASE: udp cksum mode invalid\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "udp-cksum-mode hello\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");
    
    /* Test Case - map invalid v4 addr */
    printf("TEST CASE: map invalid v4\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "map 192.168.fe.0 2001:db8::3\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - map invalid v6 addr */
    printf("TEST CASE: map invalid v6\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "map 192.168.255.0 2001:db8::hi\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - map non-matching mask */
    printf("TEST CASE: map non-matching mask\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "map 192.168.254.0/24 2001:db8::/116\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");
    
    /* Test Case - v4 has reserved addr */
    printf("TEST CASE: map reserved 4\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "map 233.0.1.1/24 2001:db8::/120\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - v6 has reserved addr */
    printf("TEST CASE: map reserved 6\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "map 192.168.0.0/24 fe80::/120\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - conflict */
    printf("TEST CASE: map4 overlaps\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "map 192.168.254.0/24 2001:db8::/120\nmap 192.168.254.0/24 2001:db8::/120\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - conflict */
    printf("TEST CASE: map6 overlaps\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "map 192.168.253.0/24 2001:db8::/120\nmap 192.168.254.0/24 2001:db8::/120\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - dyn pool duplicate */
    printf("TEST CASE: dynamic pool duplicate\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "dynamic-pool 192.168.255.0/24\ndynamic-pool 192.168.254.0/24\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - dyn pool invalid v4 */
    printf("TEST CASE: dynamic pool duplicate\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "dynamic-pool 192.268.254.0/24\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - dyn pool reserved */
    printf("TEST CASE: dynamic pool reserved\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "dynamic-pool 225.0.0.1/16\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - dyn pool /32 */
    printf("TEST CASE: dynamic pool /32\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "dynamic-pool 192.168.100.1/32\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - data dir duplicate */
    printf("TEST CASE: data dir duplicate\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "data-dir /var/lib/tayga\ndata-dir /var/spool/tayga\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - data dir invalid */
    printf("TEST CASE: data dir relative\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "data-dir var/spool/tayga\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - strict frag header value */
    printf("TEST CASE: strict frag header invalid\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "strict-frag-hdr none\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");
    
    /* Test Case - offlink mtu  */
    printf("TEST CASE: offlink mtu duplicate\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "offlink-mtu 1500\nofflink-mtu 1440\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - offlink mtu  */
    printf("TEST CASE: offlink mtu too low\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "offlink-mtu 1200\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - offlink mtu  */
    printf("TEST CASE: offlink mtu too high\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "offlink-mtu 120000\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - offlink mtu  */
    printf("TEST CASE: offlink mtu not a number\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "offlink-mtu 0x1235\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");
    
    /* Test Case - log duplicate*/
    printf("TEST CASE: log duplicate\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "log drop\nlog reject\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - log invalid arg*/
    printf("TEST CASE: log invalid arg\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "log something\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - unknown option  */
    printf("TEST CASE: unknown option\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "unbknown 4\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - unknown option  */
    printf("TEST CASE: too many tokens\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "log a b c d e f g h i j k l m n o p\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Test Case - unknown option  */
    printf("TEST CASE: wrong number of args\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "ipv4-addr 192.168.0.0 192.168.1.0\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(config_read(conffile),"Failed");

    /* Parse all config options */
    testcase = "#config for tayga\n"
        "tun-device nat64\n"
        "ipv4-addr 192.168.255.1\n"
        "ipv6-addr 2001:db8:1::2\n"
        "prefix 64:ff9b::/96\n"
        "wkpf-strict yes\n"
        "dynamic-pool 192.168.255.0/24\n"
        "data-dir /var/lib/tayga\n"
        "map 192.168.5.42 2001:db8:1:4444::1\n"
        "map 192.168.6.0/24 2001:db8:1:4445::/120\n"
        "udp-cksum-mode drop\n"
        "log drop reject icmp self\n"
        "offlink-mtu 1492\n";
    printf("TEST CASE: all config options\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;;
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(!config_read(conffile),"Passed");
    strcpy(tcfg.data_dir,"/var/lib/tayga");
    strcpy(tcfg.tundev,"nat64");
    tcfg.local_addr4.s_addr = htonl(0xc0a8ff01);
    tcfg.local_addr6.s6_addr32[0] = htonl(0x20010db8);
    tcfg.local_addr6.s6_addr32[1] = htonl(0x00010000);
    tcfg.local_addr6.s6_addr32[3] = htonl(0x00000002);
    tcfg.ipv6_offlink_mtu = 1492;
    tcfg.log_opts = (LOG_OPT_DROP | LOG_OPT_ICMP | LOG_OPT_REJECT | LOG_OPT_SELF | LOG_OPT_CONFIG);
    tmap4[0] = "192.168.5.42/32 type 0 mask 255.255.255.255";
    tmap4[1] = "192.168.255.0/24 type 2 mask 255.255.255.0";
    tmap4[2] = "192.168.6.0/24 type 0 mask 255.255.255.0";
    tmap4[3] = "0.0.0.0/0 type 1 mask 0.0.0.0";
    tmap4[4] = 0;
    tmap6[0] = "2001:db8:1:4444::1/128 type 0 mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
    tmap6[1] = "2001:db8:1:4445::/120 type 0 mask ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00";
    tmap6[2] = "64:ff9b::/96 type 1 mask ffff:ffff:ffff:ffff:ffff:ffff::";
    tmap6[3] = 0;
    test_config_compare();    
}

void test_config_validate() {
    char * conffile = "unit_conffile.conf";
    FILE * fd;
    char * testcase;
    tmap4[0] = 0;
    tmap6[0] = 0;

    
    /* No config loading has been done */
    printf("TEST CASE: no config loaded\n");
    free(gcfg);
    config_init();
    expect(config_validate(),"Validate Failed");

    /* Empty conf file */
    printf("TEST CASE: read an empty conf file\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "#hello\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");

    
    /* Only a prefix */
    printf("TEST CASE: prefix only\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");
    
    /* ipv4-addr */
    printf("TEST CASE: prefix, ipv4\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");
    
    /* ipv4-addr overlaps with map */
    printf("TEST CASE: ipv4 overlaps with map\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "map 192.168.255.0 2001:db8::1\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");

    
    /* ipv6-addr is within well known prefix */
    printf("TEST CASE: ipv6 within wkpf\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "ipv6-addr 64:ff9b::1\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");

    /* ipv6-addr is within configured prefix */
    printf("TEST CASE: ipv6 within prefix\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 3fff:6464::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "ipv6-addr 3fff:6464::1\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");

    /* ipv6-addr overlap */
    printf("TEST CASE: ipv6 within prefix\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "ipv6-addr 2001:db8::1\n"
        "map 192.168.255.1 2001:db8::1\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");
    
    /* prefix not specified */
    printf("TEST CASE: no prefix no ipv6-addr\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "ipv4-addr 192.168.255.0\n"
        "map 192.168.255.1 2001:db8::1\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");

    /* no tun device */
    printf("TEST CASE: no tun-device\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "ipv6-addr 2001:db8::1\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");
    
    /* wkfp not strict and non global addr */
    printf("TEST CASE: no prefix no ipv6-addr\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "wkpf-strict no\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 1;
    expect(!config_read(conffile),"Read Passed");
    /* Combined with offlink MTU test*/
    gcfg->ipv6_offlink_mtu = 0;
    expect(!config_validate(),"Validate Passed");
    expectl(gcfg->ipv6_offlink_mtu,MTU_MIN,"Min MTU");
    expectl(getenv_case,0,"Getenv Called");
    /* Combined with STATE_DIRECTORY test */
    expects(gcfg->data_dir,"/var/lib/tayga",15,"data_dir");

    /* state directory not absolute */
    printf("TEST CASE: state dir not absolute\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "wkpf-strict no\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 2;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");
    
    /* state directory too long */
    printf("TEST CASE: state dir too long\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "wkpf-strict no\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 3;
    expect(!config_read(conffile),"Read Passed");
    expect(config_validate(),"Validate Failed");
    expectl(getenv_case,0,"Getenv Called");   

    /* state directory multiple paths */
    printf("TEST CASE: state dir multiple paths\n");
    fd = fopen(conffile,"w");
    expect((long)fd,"fopen");
    if(!fd) return;
    testcase = "prefix 64:ff9b::/96\n"
        "ipv4-addr 192.168.255.0\n"
        "wkpf-strict no\n"
        "tun-device nat64\n";
    fwrite(testcase,strlen(testcase),1,fd);
    fclose(fd);
    free(gcfg);
    config_init();
    getenv_case = 4;
    expect(!config_read(conffile),"Read Passed");
    expect(!config_validate(),"Validate Passed");
    expectl(getenv_case,0,"Getenv Called");
    expects(gcfg->data_dir,"/var/lib/tayga",15,"data_dir");
}

int main(void) {
    /* Test function or config_init */
    test_config_init();

    /* Test function for config_read */
    test_config_read();

    /* Test function for config_validate */
    test_config_validate();
    
    /* Return final status */
    return overall();
}