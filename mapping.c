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
    /* Malloc an initial size for the table, but it is empty */
    gcfg.map_entry_size = 16;
    gcfg.map_entry_len = 0;
    gcfg.map4 = malloc(gcfg.map_entry_size * sizeof(struct map_entry));
    if(!gcfg.map4) {
        slog(LOG_CRIT,"Failed to allocate map4\n");
        exit(-1);
    }
    gcfg.map6 = malloc(gcfg.map_entry_size * sizeof(struct map_entry));
    if(!gcfg.map6) {
        slog(LOG_CRIT,"Failed to allocate map6\n");
        exit(-1);
    }
}

/**
 * @brief Insert a static map entry into the static map lists
 * 
 * Takes a given static map entry and inserts it at the correct
 * location in the map4 and map6 lists
 *
 * @param m struct map_entry to add
 * @returns Nonzero on error
 */
int map_insert(struct map_entry *m) {
    /* Bail if entry is invalid */
    if(!m) return -1;
    if(m->prefix_len4 > 32) return -1;
    if(m->prefix_len4 < 0) return -1;
    if(m->prefix_len6 > 128) return -1;
    if(m->prefix_len6 < 0) return -1;
    if(m->type >= MAP_TYPE_MAX) return -1;

    /* Check to see if we have enough space in the list */
    if(gcfg.map_entry_len >= gcfg.map_entry_size) {
        /* Double the size of the list, malloc new lists */
        int newsize = gcfg.map_entry_size * 2;
        slog(LOG_DEBUG,"Reallocating maps to larger size (now %d)\n",newsize);
        struct map_entry * new4 = malloc(newsize * sizeof(struct map_entry));
        if(!new4) {
            slog(LOG_CRIT,"Failed to reallocate map4\n");
            exit(-1);
        }
        struct map_entry * new6 = malloc(newsize * sizeof(struct map_entry));
        if(!new6) {
            slog(LOG_CRIT,"Failed to reallocate map6\n");
            exit(-1);
        }
        /* Copy old map to new map, then free old map */
        memcpy(new4,gcfg.map4,gcfg.map_entry_len*sizeof(struct map_entry));
        memcpy(new6,gcfg.map6,gcfg.map_entry_len*sizeof(struct map_entry));
        free(gcfg.map4);
        gcfg.map4 = new4;
        free(gcfg.map6);
        gcfg.map6 = new6;
        gcfg.map_entry_size = newsize;
    }

    /* Find the insertion point (shortest prefix match) */
    int insert_pt = gcfg.map_entry_len;
    for(int i = 0; i < gcfg.map_entry_len; i++) {
        if(m->prefix_len4 > gcfg.map4[i].prefix_len4) {
            insert_pt = i;
            break;
        }
    }
    /* Memcpy the array down one index */
    int insert_len = gcfg.map_entry_len - insert_pt;
    memmove(&gcfg.map4[insert_pt+1],&gcfg.map4[insert_pt],insert_len*sizeof(struct map_entry));

    /* Copy our struct into the map */
    memcpy(&gcfg.map4[insert_pt],m,sizeof(struct map_entry));
    
    /* Now do it all again for the v6 table */
    insert_pt = gcfg.map_entry_len;
    for(int i = 0; i < gcfg.map_entry_len; i++) {
        if(m->prefix_len6 > gcfg.map6[i].prefix_len6) {
            insert_pt = i;
            break;
        }
    }
    insert_len = gcfg.map_entry_len - insert_pt;
    memmove(&gcfg.map6[insert_pt+1],&gcfg.map6[insert_pt],insert_len*sizeof(struct map_entry));
    memcpy(&gcfg.map6[insert_pt],m,sizeof(struct map_entry));

    /* Increment entry length */
    gcfg.map_entry_len++;
    
    return 0;
}

/**
 * @brief Search for the map entry for an IPv4 address
 * 
 * Takes a given IPv4 address and finds the corresponding map
 *
 * @param a ipv4 address
 * @returns Pointer to map entry, or NULL on error
 */
struct map_entry *map_search4(struct in_addr a) {
    for(int i = 0; i < gcfg.map_entry_len; i++)
    {
        /* Compare to this mapping entry */
        if((gcfg.map4[i].prefix_len4 == 32 && 
             gcfg.map4[i].addr4.s_addr == a.s_addr) ||
           (gcfg.map4[i].addr4.s_addr ==
            (a.s_addr & htonl(~(0xffffffff >> gcfg.map4[i].prefix_len4))))) {
            return &gcfg.map4[i];
        }
    }
    /* Not found */
    return NULL;
}

/**
 * @brief Search for the map entry for an IPv6 address
 * 
 * Takes a given IPv6 address and finds the corresponding map
 *
 * @param a ipv6 address
 * @returns Pointer to map entry, or NULL on error
 */
struct map_entry *map_search6(struct in6_addr a) {
    for(int i = 0; i < gcfg.map_entry_len; i++)
    {
        /* Short prefixes compare 1 word */
        if(gcfg.map6[i].prefix_len6 < 32 && 
            gcfg.map6[i].addr6.s6_addr32[0] ==
            (a.s6_addr32[0] & htonl(~(0xffffffff >> gcfg.map6[i].prefix_len6)))) {
            return &gcfg.map6[i];
        /* 2 word prefixes */
        } else if (gcfg.map6[i].prefix_len6 < 64 && 
            gcfg.map6[i].addr6.s6_addr32[0] == a.s6_addr32[0] &&
            gcfg.map6[i].addr6.s6_addr32[1] ==
            (a.s6_addr32[1] & htonl(~(0xffffffff >> (gcfg.map6[i].prefix_len6-32))))) {
        return &gcfg.map6[i];
        /* 3 word prefixes */
        } else if (gcfg.map6[i].prefix_len6 < 96 && 
            gcfg.map6[i].addr6.s6_addr32[0] == a.s6_addr32[0] &&
            gcfg.map6[i].addr6.s6_addr32[1] == a.s6_addr32[1] &&
            gcfg.map6[i].addr6.s6_addr32[2] ==
            (a.s6_addr32[2] & htonl(~(0xffffffff >> (gcfg.map6[i].prefix_len6-64))))) {
        return &gcfg.map6[i];
        /* 4 word prefixes */
        } else if (gcfg.map6[i].prefix_len6 < 128 && 
            gcfg.map6[i].addr6.s6_addr32[0] == a.s6_addr32[0] &&
            gcfg.map6[i].addr6.s6_addr32[1] == a.s6_addr32[1] &&
            gcfg.map6[i].addr6.s6_addr32[2] == a.s6_addr32[2] &&
            gcfg.map6[i].addr6.s6_addr32[3] ==
            (a.s6_addr32[3] & htonl(~(0xffffffff >> (gcfg.map6[i].prefix_len6-96))))) {
        return &gcfg.map6[i];
        /* full prefixes */
        } else if (gcfg.map6[i].addr6.s6_addr32[0] == a.s6_addr32[0] &&
            gcfg.map6[i].addr6.s6_addr32[1] == a.s6_addr32[1] &&
            gcfg.map6[i].addr6.s6_addr32[2] == a.s6_addr32[2] &&
            gcfg.map6[i].addr6.s6_addr32[3] == a.s6_addr32[3]) {
        return &gcfg.map6[i];
        }
    }

    /* Not found */
    return NULL;
}