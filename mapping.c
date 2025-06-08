/*
 *  mapping.c - map v4 and v6 addresses using a variety of algorithms
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

/**
 * @brief Initialize mapping tables
 * 
 * Allocates space for mapping tables, exits on failure
 */
void map_init(void) {
    /* Malloc the tree root */
    gcfg.map4 = malloc(sizeof(struct map_entry));
    if(!gcfg.map4) {
        slog(LOG_CRIT,"Failed to allocate tree root\n");
        exit(-1);
    }
    /* Zero buffer */
    memset(gcfg.map4,0,sizeof(struct map_entry));

    /* Set referenced flags */
    gcfg.map4->flags |= MAP_F_REF4 | MAP_F_REF6;

    /* Use the same entry for IPv6 */
    gcfg.map6 = gcfg.map4;
}

/**
 * @brief Insert a static map entry into the static map trie(s)
 * 
 * Takes a given static map entry and inserts it at the correct
 * location in the map, for both v4 and v6
 *
 * @param m struct map_entry to add
 * @param op bitmask of MAP_OPT flags to perform
 * @returns Nonzero on error
 */
int map_insert(struct map_entry *m, int op) {
    /* Bail if entry is invalid */
    if(!m) return -1;
    if(m->prefix4 > 32) return -1;
    if(m->prefix4 < 0) return -1;
    if(m->type >= MAP_TYPE_MAX) return -1;

    /* TBD */
    return 0;
}

/**
 * @brief Search for the map entry (common)
 * 
 * Search for a map entry in a given table
 *
 * @param a ip address
 * @returns Pointer to map entry, or NULL on error
 */
static struct map_entry *map_search(struct trie_entry *trie,struct in6_addr *a) {
    /* For loop bounds us to max 128 iterations */
    for(int i = 0; i < 128; i++) {
        int bit = trie->bit;
        int dir = (a->s6_addr[((bit & 0x78) >> 3)] & (1 << (bit & 0x7)));
        struct trie_entry *next = (dir) ? (trie->right) : (trie->left);
        if(!next) {
            /* No further entries */
            break;
        } 
        trie = next;
    }

    /* Starting with value in map, backtrack until we find an exact match */
    for(int i = 0; i < 128; i++) {
        if(IN6_IS_IN_NET(a,&trie->addr,&trie->mask)) {
            /* Found an exact match */
            return trie->map;
        }
        /* Ensure we don't go beyond the top */
        if(trie->parent) {
            /* Backtrack */
            trie = trie->parent;
        }
    }
    /* Iterated more than 128 times, odd also */
    return NULL;
}

/**
 * @brief Search for the map entry for an IPv4 address
 * 
 * Takes a given IPv4 address and finds the corresponding map
 *
 * @param a ipv4 address
 * @returns Pointer to map entry, or NULL on error
 */
struct map_entry *map_search4(struct in_addr *a) {
    /* Call common function with map4 */
    return map_search(gcfg.map4,(struct in6_addr *)a);
}
/**
 * @brief Search for the map entry for an IPv6 address
 * 
 * Takes a given IPv6 address and finds the corresponding map
 *
 * @param a ipv6 address
 * @returns Pointer to map entry, or NULL on error
 */
struct map_entry *map_search6(struct in6_addr *a) {
    /* Call common function with map6 */
    return map_search(gcfg.map6,a);
}