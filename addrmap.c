/*
 *  addrmap.c -- address mapping routines
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

extern struct config *gcfg;
extern time_t now;

/**
 * @brief Check if an IPv4 address is valid
 * 
 * Checks if an address is within the ranges which are reserved
 * by protocol, such as multicast, link-local, etc.
 *
 * @param a struct in_addr address to validate
 * @returns ERROR_DROP if invalid, else 0
 */
int validate_ip4_addr(const struct in_addr *a)
{
	/* First Octet == 0 */
	if ((a->s_addr & htonl(0xff000000)) == htonl(0x00000000))
		return ERROR_DROP;
	/* First octet == 127 */
	if ((a->s_addr & htonl(0xff000000)) == htonl(0x7f000000))
		return ERROR_DROP;

	/* Link-local block 169.254.0.0/16 */
	if ((a->s_addr & htonl(0xffff0000)) == htonl(0xa9fe0000))
		return ERROR_DROP;

	/* Class D */
	if ((a->s_addr & htonl(0xf0000000)) == htonl(0xe0000000))
		return ERROR_DROP;

	/* Class E considered valid now */

	/* Local Broadcast not considered valid */
	if (a->s_addr== 0xffffffff)
		return ERROR_DROP;

	return ERROR_NONE;
}

/**
 * @brief Check if an IPv6 address is valid
 *  
 * Checks if an address is within the ranges which are reserved
 * by protocol, such as multicast, link-local, etc.
 *
 * @param a struct in6_addr address to validate
 * @returns ERROR_DROP if invalid, else 0
 */
int validate_ip6_addr(const struct in6_addr *a)
{
	/* Well-known prefix for NAT64, plus Local-Use Space */
	if (a->s6_addr32[0] == WKPF)
		return ERROR_NONE;


	/* Reserved per RFC 2373 */
	if (!a->s6_addr[0])
		return ERROR_DROP;

	/* Multicast addresses */
	if (a->s6_addr[0] == 0xff)
		return ERROR_DROP;

	/* Link-local unicast addresses */
	if ((a->s6_addr16[0] & htons(0xffc0)) == htons(0xfe80))
		return ERROR_DROP;

	return ERROR_NONE;
}

/**
 * @brief Check if an IPv4 address is private
 *  
 * Checks if an address is within the ranges which are reserved
 * by IANA, and therefore, must not be translated using the
 * well-known prefix (64:ff9b::/96)
 *
 * @param a struct in_addr address to validate
 * @returns ERROR_REJECT if invalid, else 0
 */
int is_private_ip4_addr(const struct in_addr *a)
{
	/* 10.0.0.0/8 RFC1918 */
	if ((a->s_addr & htonl(0xff000000)) == htonl(0x0a000000))
		return ERROR_REJECT;

	/* 100.64.0.0/10 RFC6598 */
	if ((a->s_addr & htonl(0xffc00000)) == htonl(0x64400000))
		return ERROR_REJECT;

	/* 172.16.0.0/12 RFC1918 */
	if ((a->s_addr & htonl(0xfff00000)) == htonl(0xac100000))
		return ERROR_REJECT;

	/* 192.0.2.0/24 RFC5737 */
	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xc0000200))
		return ERROR_REJECT;

	/* 192.168.0.0/16 RFC1918 */
	if ((a->s_addr & htonl(0xffff0000)) == htonl(0xc0a80000))
		return ERROR_REJECT;

	/* 198.18.0.0/15 RFC2544 */
	if ((a->s_addr & htonl(0xfffe0000)) == htonl(0xc6120000))
		return ERROR_REJECT;

	/* 198.51.100.0/24 RFC5737 */
	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xc6336400))
		return ERROR_REJECT;

	/* 203.0.113.0/24 RFC5737 */
	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xcb007100))
		return ERROR_REJECT;

	return ERROR_NONE;
}

/**
 * @brief Calculate the mask of an IPv4 address
 *
 * @param mask Pointer to return mask
 * @param addr Pointer to address
 * @param len length in bits of IPv4 mask
 * @returns -1 if address has host bits of mask set
 */
int calc_ip4_mask(struct in_addr *mask, const struct in_addr *addr, int len)
{
	mask->s_addr = htonl(~(0xffffffff >> len));
	if (len == 32) mask->s_addr = 0xffffffff;
	if (addr && (addr->s_addr & ~mask->s_addr))
		return -1;
	return 0;
}

/**
 * @brief Calculate the mask of an IPv6 address
 *
 * @param mask Pointer to return mask
 * @param addr Pointer to address
 * @param len length in bits of IPv6 mask
 * @returns -1 if address has host bits of mask set
 */
int calc_ip6_mask(struct in6_addr *mask, const struct in6_addr *addr, int len)
{
	if (len > 32) {
		mask->s6_addr32[0] = ~0;
		if (len > 64) {
			mask->s6_addr32[1] = ~0;
			if (len > 96) {
				mask->s6_addr32[2] = ~0;
				mask->s6_addr32[3] =
					htonl(~((1 << (128 - len)) - 1));
			} else {
				mask->s6_addr32[2] =
					htonl(~((1 << (96 - len)) - 1));
				mask->s6_addr32[3] = 0;
			}
		} else {
			mask->s6_addr32[1] = htonl(~((1 << (64 - len)) - 1));
			mask->s6_addr32[2] = 0;
			mask->s6_addr32[3] = 0;
		}
	} else {
		mask->s6_addr32[0] = htonl(~((1 << (32 - len)) - 1));
		mask->s6_addr32[1] = 0;
		mask->s6_addr32[2] = 0;
		mask->s6_addr32[3] = 0;
	}
	if (!addr)
		return 0;
	if ((addr->s6_addr32[0] & ~mask->s6_addr32[0]) ||
			(addr->s6_addr32[1] & ~mask->s6_addr32[1]) ||
			(addr->s6_addr32[2] & ~mask->s6_addr32[2]) ||
			(addr->s6_addr32[3] & ~mask->s6_addr32[3]))
		return -1;
	return 0;
}

static uint32_t hash_ip4(const struct in_addr *addr4)
{
	return ((uint32_t)(addr4->s_addr *
				gcfg.rand[0])) >> (32 - gcfg.hash_bits);
}

static uint32_t hash_ip6(const struct in6_addr *addr6)
{
	uint32_t h;
	h = addr6->s6_addr32[0] + gcfg.rand[0];
	h ^= addr6->s6_addr32[1] + gcfg.rand[1];
	h ^= addr6->s6_addr32[2] + gcfg.rand[2];
	h ^= addr6->s6_addr32[3] + gcfg.rand[3];
	return h >> (32 - gcfg.hash_bits);
}

/**
 * @brief Append an IPv4 address to an IPv6 translation prefix
 *  
 * @param[out] addr6 Return IPv6 address
 * @param[in] addr4 IPv4 address
 * @param[in] prefix IPv6 Prefix
 * @param[in] prefix_len IPv6 prefix length (must be defined by RFC6052)
 * @returns ERROR_DROP on invalid prefix
 */
int append_to_prefix(struct in6_addr *addr6, const struct in_addr addr4,
		const struct in6_addr *prefix, int prefix_len)
{
	switch (prefix_len) {
	case 32:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
		addr6->s6_addr32[1] = addr4.s_addr;
		addr6->s6_addr32[2] = 0;
		addr6->s6_addr32[3] = 0;
		return ERROR_NONE;
	case 40:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
#if __BYTE_ORDER == __BIG_ENDIAN
		addr6->s6_addr32[1] = prefix->s6_addr32[1] |
					(addr4.s_addr >> 8);
		addr6->s6_addr32[2] = (addr4.s_addr << 16) & 0x00ff0000;
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN
		addr6->s6_addr32[1] = prefix->s6_addr32[1] |
					(addr4.s_addr << 8);
		addr6->s6_addr32[2] = (addr4.s_addr >> 16) & 0x0000ff00;
# endif
#endif
		addr6->s6_addr32[3] = 0;
		return ERROR_NONE;
	case 48:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
#if __BYTE_ORDER == __BIG_ENDIAN
		addr6->s6_addr32[1] = prefix->s6_addr32[1] |
					(addr4.s_addr >> 16);
		addr6->s6_addr32[2] = (addr4.s_addr << 8) & 0x00ffff00;
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN
		addr6->s6_addr32[1] = prefix->s6_addr32[1] |
					(addr4.s_addr << 16);
		addr6->s6_addr32[2] = (addr4.s_addr >> 8) & 0x00ffff00;
# endif
#endif
		addr6->s6_addr32[3] = 0;
		return ERROR_NONE;
	case 56:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
#if __BYTE_ORDER == __BIG_ENDIAN
		addr6->s6_addr32[1] = prefix->s6_addr32[1] |
					(addr4.s_addr >> 24);
		addr6->s6_addr32[2] = addr4.s_addr & 0x00ffffff;
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN
		addr6->s6_addr32[1] = prefix->s6_addr32[1] |
					(addr4.s_addr << 24);
		addr6->s6_addr32[2] = addr4.s_addr & 0xffffff00;
# endif
#endif
		addr6->s6_addr32[3] = 0;
		return ERROR_NONE;
	case 64:
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
		addr6->s6_addr32[1] = prefix->s6_addr32[1];
#if __BYTE_ORDER == __BIG_ENDIAN
		addr6->s6_addr32[2] = addr4.s_addr >> 8;
		addr6->s6_addr32[3] = addr4.s_addr << 24;
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN
		addr6->s6_addr32[2] = addr4.s_addr << 8;
		addr6->s6_addr32[3] = addr4.s_addr >> 24;
# endif
#endif
		return ERROR_NONE;
	case 96:
		//Do not allow translation of well-known prefix
		//But still allow local-use prefix
		if (prefix->s6_addr32[0] == WKPF && 
			!prefix->s6_addr32[1] && 
			!prefix->s6_addr32[2] && 
			gcfg.wkpf_strict &&
			is_private_ip4_addr(addr4))
			return ERROR_REJECT;
		addr6->s6_addr32[0] = prefix->s6_addr32[0];
		addr6->s6_addr32[1] = prefix->s6_addr32[1];
		addr6->s6_addr32[2] = prefix->s6_addr32[2];
		addr6->s6_addr32[3] = addr4.s_addr;
		return ERROR_NONE;
	default:
		return ERROR_DROP;
	}
}

/**
 * @brief Map IPv4 to IPv6
 *  
 * @param[out] addr6 Return IPv6 address
 * @param[in] addr4 IPv4 address
 * @param[out] map_ptr Pointer to map4 entry
 * @returns ERROR_REJECT or ERROR_DROP on error
 */
int map_ip4_to_ip6(struct in6_addr *addr6, const struct in_addr addr4,
		struct map_entry *map_ptr)
{
	int ret;

	/* Search for mapping entry */
	struct map_entry *map4 = map_search4(addr4);

	if (!map4) {
		slog(LOG_DEBUG,"Invalid map4 at %s:%d\n",__FUNCTION__,__LINE__);
		return ERROR_REJECT;
	}

	switch (map4->type) {
	/* Explicit Address / Static Mapping */
	case MAP_TYPE_STATIC:
		/* Copy whole IPv6 address to start */
		*addr6 = map4->addr6;
		/* If this is not a single host, keep some bits from the addr4 */
		if (map4->prefix_len4 < 32) {
			addr6->s6_addr32[3] = map4->addr4.s_addr | (addr4.s_addr & htonl(~(0xffffffff >> map4->prefix_len4)));
		}
		break;
	/* RFC6052 IPv4-translate-IPv6 encoding */
	case MAP_TYPE_RFC6052:
		ret = append_to_prefix(addr6, addr4, &map4->addr6,map4->prefix_len6);
		if (ret < 0) {
			slog(LOG_DEBUG,"Append_to_prefix failed at %s:%d\n",__FUNCTION__,__LINE__);
			return ret;
		}
		break;
	/* Dynamic pool mapping */
	case MAP_TYPE_DYNAMIC:
		slog(LOG_DEBUG,"Address map is dynamic pool at %s:%d\n",__FUNCTION__,__LINE__);
		return ERROR_REJECT;
	default:
		slog(LOG_DEBUG,"Hit default case in %s:%d\n",__FUNCTION__,__LINE__);
		return ERROR_DROP;
	}

	if(map_ptr) *map_ptr = map4;
	return ERROR_NONE;
}

static int extract_from_prefix(struct in_addr *addr4,
		const struct in6_addr *addr6, int prefix_len)
{
	switch (prefix_len) {
	case 32:
		if (addr6->s6_addr32[2] || addr6->s6_addr32[3])
			return ERROR_DROP;
		addr4->s_addr = addr6->s6_addr32[1];
		break;
	case 40:
		if (addr6->s6_addr32[2] & htonl(0xff00ffff) ||
				addr6->s6_addr32[3])
			return ERROR_DROP;
#if __BYTE_ORDER == __BIG_ENDIAN
		addr4->s_addr = (addr6->s6_addr32[1] << 8) | addr6->s6_addr[9];
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN
		addr4->s_addr = (addr6->s6_addr32[1] >> 8) |
				(addr6->s6_addr32[2] << 16);
# endif
#endif
		break;
	case 48:
		if (addr6->s6_addr32[2] & htonl(0xff0000ff) ||
				addr6->s6_addr32[3])
			return ERROR_DROP;
#if __BYTE_ORDER == __BIG_ENDIAN
		addr4->s_addr = (addr6->s6_addr16[3] << 16) |
				(addr6->s6_addr32[2] >> 8);
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN
		addr4->s_addr = addr6->s6_addr16[3] |
				(addr6->s6_addr32[2] << 8);
# endif
#endif
		break;
	case 56:
		if (addr6->s6_addr[8] || addr6->s6_addr32[3])
			return ERROR_DROP;
#if __BYTE_ORDER == __BIG_ENDIAN
		addr4->s_addr = (addr6->s6_addr[7] << 24) |
				addr6->s6_addr32[2];
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN
		addr4->s_addr = addr6->s6_addr[7] |
				addr6->s6_addr32[2];
# endif
#endif
		break;
	case 64:
		if (addr6->s6_addr[8] ||
				addr6->s6_addr32[3] & htonl(0x00ffffff))
			return ERROR_DROP;
#if __BYTE_ORDER == __BIG_ENDIAN
		addr4->s_addr = (addr6->s6_addr32[2] << 8) |
				addr6->s6_addr[12];
#else
# if __BYTE_ORDER == __LITTLE_ENDIAN
		addr4->s_addr = (addr6->s6_addr32[2] >> 8) |
				(addr6->s6_addr32[3] << 24);
# endif
#endif
		break;
	case 96:
		addr4->s_addr = addr6->s6_addr32[3];
		break;
	default:
		return ERROR_DROP;
	}
	return validate_ip4_addr(addr4);
}
/**
 * @brief Map IPv6 to IPv4
 *  
 * @param[out] addr4 Return IPv6 address
 * @param[in] addr6 IPv4 address
 * @param[out] map_ptr Map entry
 * @param[in] dyn_allow Allow dynamic allocation for this mapping
 * @returns ERROR_REJECT or ERROR_DROP on error
 */
int map_ip6_to_ip4(struct in_addr *addr4, const struct in6_addr *addr6,
		struct map_entry **map_ptr, int dyn_alloc)
{
	int ret = 0;
	struct map_entry *map6 = map_search6(*addr6);

	if (!map6) {
		slog(LOG_DEBUG,"Droppnig packet due to no mapping entry\n");
		return ERROR_REJECT;
	}

	switch (map6->type) {
	/* Static / EAM map */
	case MAP_TYPE_STATIC:
		if (map6->prefix_len6 < 128) {
			addr4->s_addr = map6->addr4.s_addr | (map6->addr6.s6_addr32[3] & htonl(~(0xffffffff >> map6->prefix_len4)));
		} else {
			*addr4 = map6->addr4;
		}

		break;
	/* RFC6052 map */
	case MAP_TYPE_RFC6052:
		ret = extract_from_prefix(addr4, addr6, map6->prefix_len6);
		if (ret < 0)
			return ret;
		if (map6->addr.s6_addr32[0] == WKPF &&
			map6->addr.s6_addr32[1] == 0 &&
			map6->addr.s6_addr32[2] == 0 &&
			gcfg.wkpf_strict &&
				is_private_ip4_addr(addr4))
			return ERROR_REJECT;
		/* Check for hairpin was previously here */
		break;
	/* Dynamic map */
	case MAP_TYPE_DYNAMIC:
		/* TODO */
		return ERROR_DROP;
		break;
	default:
		slog(LOG_DEBUG,"Dropping packet due to default case %s:%d",__FUNCTION__,__LINE__);
		return ERROR_DROP;
	}

	if(map_ptr) *map_ptr = map6;
	return ERROR_NONE;
}