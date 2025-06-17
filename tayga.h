/*
 *  tayga.h -- main header file
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

#include <stdio.h>
#include <assert.h>
#include <stdalign.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <poll.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/if.h>
#include <net/if_tun.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/uio.h>
#else
#error "Could not find headers for platform"
#endif
#include "list.h"

#ifdef COVERAGE_TESTING
//for coverage testing
inline static void dummy()
{
	volatile static int temp;
	temp++;
}
#else
#define dummy()
#endif


#ifdef __linux__
#define	TUN_SET_PROTO(_pi, _af)			{ (_pi)->flags = 0; (_pi)->proto = htons(_af); }
#define	TUN_GET_PROTO(_pi)			ntohs((_pi)->proto)
#endif

#ifdef __FreeBSD__
#define s6_addr8  __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32

struct tun_pi {
	int	proto;
};

#define ETH_P_IP AF_INET
#define	ETH_P_IPV6 AF_INET6
#define	TUN_SET_PROTO(_pi, _af)			{ (_pi)->proto = htonl(_af); }
#define	TUN_GET_PROTO(_pi)			ntohl((_pi)->proto)
#endif

/* Configuration knobs */

/* Number of seconds between dynamic pool ageing passes */
#define POOL_CHECK_INTERVAL	45

/* Valid token delimiters in config file and dynamic map file */
#define DELIM		" \t\r\n"

/// Default configuration path
#define TAYGA_CONF_PATH "/etc/tayga.conf"


/* Protocol structures */

struct ip4 {
	uint8_t ver_ihl; /* 7-4: ver==4, 3-0: IHL */
	uint8_t tos;
	uint16_t length;
	uint16_t ident;
	uint16_t flags_offset; /* 15-13: flags, 12-0: frag offset */
	uint8_t ttl;
	uint8_t proto;
	uint16_t cksum;
	struct in_addr src;
	struct in_addr dest;
};

static_assert(alignof(struct ip4) <= 4);
static_assert(sizeof(struct ip4) == 20);

#define IP4_F_DF	0x4000
#define IP4_F_MF	0x2000
#define IP4_F_MASK	0x1fff

struct ip6 {
	uint32_t ver_tc_fl; /* 31-28: ver==6, 27-20: traf cl, 19-0: flow lbl */
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t hop_limit;
	struct in6_addr src;
	struct in6_addr dest;
};

static_assert(alignof(struct ip6) <= 4);
static_assert(sizeof(struct ip6) == 40);

struct ip6_frag {
	uint8_t next_header;
	uint8_t reserved;
	uint16_t offset_flags; /* 15-3: frag offset, 2-0: flags */
	uint32_t ident;
};

static_assert(alignof(struct ip6_frag) <= 4);
static_assert(sizeof(struct ip6_frag) == 8);

#define IP6_F_MF	0x0001
#define IP6_F_MASK	0xfff8

struct icmp {
	uint8_t type;
	uint8_t code;
	uint16_t cksum;
	uint32_t word;
};

static_assert(alignof(struct icmp) <= 4);
static_assert(sizeof(struct icmp) == 8);

#define	WKPF	(htonl(0x0064ff9b))

/* Adjusting the MTU by 20 does not leave room for the IP6 fragmentation
   header, for fragments with the DF bit set.  Follow up with BEHAVE on this.

   (See http://www.ietf.org/mail-archive/web/behave/current/msg08499.html)
 */
#define MTU_ADJ		20

/* Minimum MTU allowed by IPv6 */
#define MTU_MIN 1280


/* TAYGA data definitions */

/// Packet structure
struct pkt {
	struct ip4 *ip4;
	struct ip6 *ip6;
	struct ip6_frag *ip6_frag;
	struct icmp *icmp;
	uint8_t data_proto;
	uint8_t *data;
	uint32_t data_len;
	uint32_t header_len; /* inc IP hdr for v4 but excl IP hdr for v6 */
};

// Ensure that the data field has enough alignment for ip4 and ip6 structs
static_assert((offsetof(struct pkt, data) & (alignof(struct ip4) - 1)) == 0);
static_assert((offsetof(struct pkt, data) & (alignof(struct ip6) - 1)) == 0);

/// Type of mapping in mapping list
enum map_type_t {
	MAP_TYPE_INVALID,	/* Map entry should be dropped */
	MAP_TYPE_REJECT,	/* Map entry should get ICMP rejection */
	MAP_TYPE_STATIC,	/* Static EAM map (RFC7757) */
	MAP_TYPE_DYNAMIC,	/* Dynamic EAM entry */
	MAP_TYPE_RFC6052,	/* Translated address (RFC6052) */
	MAP_TYPE_MAX		/* Flag indicating the highest valid value */
};

/// Mapping entry
/// Meaning of these fields changes when they are indexed by addr4 or addr6
struct map_entry {
	/* Mapping addresses */
	struct in6_addr addr6;
	struct in_addr addr4;
	/* Mapping type */
	enum map_type_t type;
	/* Prefix lengths */
	int prefix4;
	int prefix6;
	/* Configuration file line number */
	int line;
	/* Binary flags (many things) */
	int flags;
	/* Last time this entry was seen */
	time_t last;
};

/// Patricia Trie Entry
struct trie_entry {
	/* IP address + IP Mask (v4 uses first word only) */
	struct in6_addr addr;
	struct in6_addr mask;
	/* Pointer to parent */
	struct trie_entry *parent;
	/* Pointer to children */
	struct trie_entry *left, *right;
	/* Pointer to corresponding map entry */
	struct map_entry *map;
	/* Bit index of this entry */
	int bit;
};

static_assert(sizeof(time_t) == 8, "64-bit time_t is required");

/// Mapping entry flag bits
enum {
	MAP_F_SEEN_4TO6		= (1<<0),	/* Traffic seen 4to6 */
	MAP_F_SEEN_6TO4		= (1<<1),	/* Traffic seen 6to4 */
	MAP_F_DYN_FROM_FILE = (1<<2),	/* Dynamic map was loaded from file */
	MAP_F_HAIRPIN	 	= (1<<3),	/* Map entry is a Hairpin route */
	MAP_F_REF4 			= (1<<14),	/* Map pointer used by v4 table */
	MAP_F_REF6 			= (1<<15)	/* Map pointer used by v6 table */
};

/// Mapping insert operation flags
enum {
	MAP_OPT_CREATE	= (1<<0),	/* Add new object in mapping table */
	MAP_OPT_REPLACE	= (1<<1),	/* Replace an existing object in mapping table */
};

/// UDP Checksum options
enum udp_cksum_mode {
	UDP_CKSUM_DROP,
	UDP_CKSUM_CALC,
	UDP_CKSUM_FWD
};

/// Configuration structure
struct config {
	char tundev[IFNAMSIZ];
	char data_dir[512];
	struct in_addr local_addr4;
	struct in6_addr local_addr6;
	/* Global RFC6052 translation prefix */
	struct in6_addr pref64;
	int pref64_len;
	/* Pointer to map */
	struct trie_entry *map4;
	struct trie_entry *map6;
	/* Dynamic timers */
	int dyn_min_lease;
	int dyn_max_lease;

	/* What is this? */
	int ipv6_offlink_mtu;

	int urandom_fd;
	int tun_fd;

	uint16_t mtu;
	uint8_t *recv_buf;
	uint32_t recv_buf_size;

	uint32_t rand[8];

	/* Strict well-known-prefix checking */
	int wkpf_strict;

	/* UDP checksumming mode */
	enum udp_cksum_mode udp_cksum_mode;
};

/// Packet error codes
enum {
	ERROR_NONE = 0,
	ERROR_REJECT = -1,
	ERROR_DROP = -2,
};


/* Macros and static functions */

/* Get a pointer to the object containing x, which is of type "type" and 
 * embeds x as a field called "field" */
#define container_of(x, type, field) ({ \
		const typeof( ((type *)0)->field ) *__mptr = (x); \
		(type *)( (char *)__mptr - offsetof(type, field) );})

#define IN6_IS_IN_NET(addr,net,mask) \
		((net)->s6_addr32[0] == ((addr)->s6_addr32[0] & \
						(mask)->s6_addr32[0]) && \
		 (net)->s6_addr32[1] == ((addr)->s6_addr32[1] & \
			 			(mask)->s6_addr32[1]) && \
		 (net)->s6_addr32[2] == ((addr)->s6_addr32[2] & \
			 			(mask)->s6_addr32[2]) && \
		 (net)->s6_addr32[3] == ((addr)->s6_addr32[3] & \
			 			(mask)->s6_addr32[3]))


/* TAYGA function prototypes */

/* addrmap.c */
int validate_ip4_addr(const struct in_addr *a);
int validate_ip6_addr(const struct in6_addr *a);
int is_private_ip4_addr(const struct in_addr *a);
int calc_ip4_mask(struct in_addr *mask, const struct in_addr *addr, int len);
int calc_ip6_mask(struct in6_addr *mask, const struct in6_addr *addr, int len);
int append_to_prefix(struct in6_addr *addr6, const struct in_addr *addr4,
		const struct in6_addr *prefix, int prefix_len);
int map_ip4_to_ip6(struct in6_addr *addr6, const struct in_addr *addr4,
		struct map_entry **map_ptr);
int map_ip6_to_ip4(struct in_addr *addr4, const struct in6_addr *addr6,
		struct map_entry **map_ptr, int dyn_alloc);

/* conffile.c */
extern struct config gcfg;
void config_init(void);
void config_read(char *conffile);
void config_validate(void);

/* dynamic.c */
void dyn_init(void);
int dyn_map4(struct map_entry *m,struct in_addr a4, struct in6_addr *a6);
int dyn_map6(struct map_entry *m,struct in_addr *a4, struct in6_addr *a6, int alloc);

/* nat64.c */
void handle_ip4(struct pkt *p);
void handle_ip6(struct pkt *p);

/* tayga.c */
extern time_t now;
void slog(int priority, const char *format, ...);
void read_random_bytes(void *d, int len);

/* mapping.c */
void map_init(void);
int map_insert(struct map_entry *m, int op);
struct map_entry *map_search4(struct in_addr *a);
struct map_entry *map_search6(struct in6_addr *a);
