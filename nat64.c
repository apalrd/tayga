/*
 *  nat64.c -- IPv4/IPv6 header rewriting routines
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

extern struct config gcfg;

static uint16_t ip_checksum(void *d, int c)
{
	uint32_t sum = 0xffff;
	uint16_t *p = d;

	while (c > 1) {
		sum += *p++;
		c -= 2;
	}

	if (c)
		sum += htons(*((uint8_t *)p) << 8);

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static uint16_t ones_add(uint16_t a, uint16_t b)
{
	uint32_t sum = (uint16_t)~a + (uint16_t)~b;

	return ~((sum & 0xffff) + (sum >> 16));
}

static uint16_t ip6_checksum(struct ip6 *ip6, uint32_t data_len, uint8_t proto)
{
	uint32_t sum = 0;
	uint16_t *p;
	int i;

	for (i = 0, p = ip6->src.s6_addr16; i < 16; ++i)
		sum += *p++;
	sum += htonl(data_len) >> 16;
	sum += htonl(data_len) & 0xffff;
	sum += htons(proto);

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static uint16_t convert_cksum(struct ip6 *ip6, struct ip4 *ip4)
{
	uint32_t sum = 0;

	/* 32-bit adds */
	uint64_t temp = ~ip4->src.s_addr;
	temp += ~ip4->dest.s_addr;
	temp += ip6->src.s6_addr32[0];
	temp += ip6->src.s6_addr32[1];
	temp += ip6->src.s6_addr32[2];
	temp += ip6->src.s6_addr32[3];
	temp += ip6->dest.s6_addr32[0];
	temp += ip6->dest.s6_addr32[1];
	temp += ip6->dest.s6_addr32[2];
	temp += ip6->dest.s6_addr32[3];

	/* End-around carries */
	if (temp > 0xffffffff) temp = (temp & 0xffffffff) + (temp >> 32);
	if (temp > 0xffffffff) temp = (temp & 0xffffffff) + (temp >> 32);
	if(temp > 0xffff) temp = (temp & 0xffff) + (temp >> 16);
	if(temp > 0xffff) temp = (temp & 0xffff) + (temp >> 16);

	return (temp & 0xffff);

	/* Un-optimized code path*/
	uint16_t *p;
	int i;
	sum += ~ip4->src.s_addr >> 16;
	sum += ~ip4->src.s_addr & 0xffff;
	sum += ~ip4->dest.s_addr >> 16;
	sum += ~ip4->dest.s_addr & 0xffff;

	for (i = 0, p = ip6->src.s6_addr16; i < 16; ++i)
		sum += *p++;

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static void host_send_icmp4(uint8_t tos, struct in_addr *src,
		struct in_addr *dest, struct icmp *icmp,
		uint8_t *data, int data_len)
{
	struct {
		struct tun_pi pi;
		struct ip4 ip4;
		struct icmp icmp;
	} __attribute__ ((__packed__)) header;
	struct iovec iov[2];

	TUN_SET_PROTO(&header.pi,  ETH_P_IP);
	header.ip4.ver_ihl = 0x45;
	header.ip4.tos = tos;
	header.ip4.length = htons(sizeof(header.ip4) + sizeof(header.icmp) +
				data_len);
	header.ip4.ident = 0;
	header.ip4.flags_offset = 0;
	header.ip4.ttl = 64;
	header.ip4.proto = 1;
	header.ip4.cksum = 0;
	header.ip4.src = *src;
	header.ip4.dest = *dest;
	header.ip4.cksum = ip_checksum(&header.ip4, sizeof(header.ip4));
	header.icmp = *icmp;
	header.icmp.cksum = 0;
	header.icmp.cksum = ones_add(ip_checksum(data, data_len),
			ip_checksum(&header.icmp, sizeof(header.icmp)));
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = data;
	iov[1].iov_len = data_len;
	if (writev(gcfg.tun_fd, iov, data_len ? 2 : 1) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(errno));
}

static void host_send_icmp4_error(uint8_t type, uint8_t code, uint32_t word,
		struct pkt *orig)
{
	struct icmp icmp;
	int orig_len;

	/* Don't send ICMP errors in response to ICMP messages other than
	   echo request */
	if (orig->data_proto == 1 && orig->icmp->type != 8)
		return;

	orig_len = orig->header_len + orig->data_len;
	if (orig_len > 576 - sizeof(struct ip4) - sizeof(struct icmp))
		orig_len = 576 - sizeof(struct ip4) - sizeof(struct icmp);
	icmp.type = type;
	icmp.code = code;
	icmp.word = htonl(word);
	host_send_icmp4(0, &gcfg.local_addr4, &orig->ip4->src, &icmp,
			(uint8_t *)orig->ip4, orig_len);
}

static void host_handle_icmp4(struct pkt *p)
{
	p->data += sizeof(struct icmp);
	p->data_len -= sizeof(struct icmp);

	switch (p->icmp->type) {
	case 8:
		p->icmp->type = 0;
		host_send_icmp4(p->ip4->tos, &p->ip4->dest, &p->ip4->src,
				p->icmp, p->data, p->data_len);
		break;
	}
}


static void xlate_header_4to6(struct pkt *p, struct ip6 *ip6,
		int payload_length)
{
	ip6->ver_tc_fl = htonl((0x6 << 28) | (p->ip4->tos << 20));
	ip6->payload_length = htons(payload_length);
	ip6->next_header = p->data_proto == 1 ? 58 : p->data_proto;
	ip6->hop_limit = p->ip4->ttl;
}

static int xlate_payload_4to6(struct pkt *p, struct ip6 *ip6)
{
	uint16_t *tck;
	uint16_t cksum;

	if (p->ip4->flags_offset & htons(IP4_F_MASK))
		return 0;

	switch (p->data_proto) {
	case 1:
		cksum = ip6_checksum(ip6, htons(p->ip4->length) -
						p->header_len, 58);
		cksum = ones_add(p->icmp->cksum, cksum);
		if (p->icmp->type == 8) {
			p->icmp->type = 128;
			p->icmp->cksum = ones_add(cksum, ~(128 - 8));
		} else {
			p->icmp->type = 129;
			p->icmp->cksum = ones_add(cksum, ~(129 - 0));
		}
		return 0;
	case 17:
		if (p->data_len < 8)
			return -1;
		tck = (uint16_t *)(p->data + 6);
		if (!*tck)
			return -1; /* drop UDP packets with no checksum */
		break;
	case 6:
		if (p->data_len < 20)
			return -1;
		tck = (uint16_t *)(p->data + 16);
		break;
	default:
		return 0;
	}
	*tck = ones_add(*tck, ~convert_cksum(ip6, p->ip4));
	return 0;
}

static void xlate_4to6_data(struct pkt *p)
{
	struct {
		struct tun_pi pi;
		struct ip6 ip6;
		struct ip6_frag ip6_frag;
	} __attribute__ ((__packed__)) header;
	struct cache_entry *src = NULL, *dest = NULL;
	struct iovec iov[2];
	int no_frag_hdr = 0;
	uint16_t off = ntohs(p->ip4->flags_offset);
	int frag_size;
	int ret;

	frag_size = gcfg.ipv6_offlink_mtu;
	if (frag_size > gcfg.mtu)
		frag_size = gcfg.mtu;
	frag_size -= sizeof(struct ip6);

	ret = map_ip4_to_ip6(&header.ip6.dest, &p->ip4->dest, &dest);
	if (ret == ERROR_REJECT) {
		char temp[64];
		slog(LOG_DEBUG,"Needed to kick back ICMP4 for ip4 %s\n",
			inet_ntop(AF_INET,&p->ip4->dest,temp,64));
		host_send_icmp4_error(3, 1, 0, p);
		return;
	}
	else if(ret == ERROR_DROP) return;

	ret = map_ip4_to_ip6(&header.ip6.src, &p->ip4->src, &src);
	if (ret == ERROR_REJECT) {
		host_send_icmp4_error(3, 10, 0, p);
		return;
	}
	else if(ret == ERROR_DROP) return;

	/* We do not respect the DF flag for IP4 packets that are already
	   fragmented, because the IP6 fragmentation header takes an extra
	   eight bytes, which we don't have space for because the IP4 source
	   thinks the MTU is only 20 bytes smaller than the actual MTU on
	   the IP6 side.  (E.g. if the IP6 MTU is 1496, the IP4 source thinks
	   the path MTU is 1476, which means it sends fragments with 1456
	   bytes of fragmented payload.  Translating this to IP6 requires
	   40 bytes of IP6 header + 8 bytes of fragmentation header +
	   1456 bytes of payload == 1504 bytes.) */
	if ((off & (IP4_F_MASK | IP4_F_MF)) == 0) {
		if (off & IP4_F_DF) {
			if (gcfg.mtu - MTU_ADJ < p->header_len + p->data_len) {
				host_send_icmp4_error(3, 4,
						gcfg.mtu - MTU_ADJ, p);
				return;
			}
			no_frag_hdr = 1;
		} else if (gcfg.lazy_frag_hdr && p->data_len <= frag_size) {
			no_frag_hdr = 1;
		}
	}

	xlate_header_4to6(p, &header.ip6, p->data_len);
	--header.ip6.hop_limit;

	if (xlate_payload_4to6(p, &header.ip6) < 0)
		return;

	if (src)
		src->flags |= CACHE_F_SEEN_4TO6;
	if (dest)
		dest->flags |= CACHE_F_SEEN_4TO6;

	TUN_SET_PROTO(&header.pi,  ETH_P_IPV6);

	if (no_frag_hdr) {
		iov[0].iov_base = &header;
		iov[0].iov_len = sizeof(struct tun_pi) + sizeof(struct ip6);
		iov[1].iov_base = p->data;
		iov[1].iov_len = p->data_len;

		if (writev(gcfg.tun_fd, iov, 2) < 0)
			slog(LOG_WARNING, "error writing packet to tun "
					"device: %s\n", strerror(errno));
	} else {
		header.ip6_frag.next_header = header.ip6.next_header;
		header.ip6_frag.reserved = 0;
		header.ip6_frag.ident = htonl(ntohs(p->ip4->ident));

		header.ip6.next_header = 44;

		iov[0].iov_base = &header;
		iov[0].iov_len = sizeof(header);

		off = (off & IP4_F_MASK) * 8;
		frag_size = (frag_size - sizeof(header.ip6_frag)) & ~7;

		while (p->data_len > 0) {
			if (p->data_len < frag_size)
				frag_size = p->data_len;

			header.ip6.payload_length =
				htons(sizeof(struct ip6_frag) + frag_size);
			header.ip6_frag.offset_flags = htons(off);

			iov[1].iov_base = p->data;
			iov[1].iov_len = frag_size;

			p->data += frag_size;
			p->data_len -= frag_size;
			off += frag_size;

			if (p->data_len || (p->ip4->flags_offset &
							htons(IP4_F_MF)))
				header.ip6_frag.offset_flags |= htons(IP6_F_MF);

			if (writev(gcfg.tun_fd, iov, 2) < 0) {
				slog(LOG_WARNING, "error writing packet to "
						"tun device: %s\n",
						strerror(errno));
				return;
			}
		}
	}
}

static int parse_ip4(struct pkt *p)
{
	p->ip4 = (struct ip4 *)(p->data);

	if (p->data_len < sizeof(struct ip4))
		return -1;

	p->header_len = (p->ip4->ver_ihl & 0x0f) * 4;

	if ((p->ip4->ver_ihl >> 4) != 4 || p->header_len < sizeof(struct ip4) ||
			p->data_len < p->header_len ||
			ntohs(p->ip4->length) < p->header_len ||
			validate_ip4_addr(&p->ip4->src) ||
			validate_ip4_addr(&p->ip4->dest))
		return -1;

	if (p->data_len > ntohs(p->ip4->length))
		p->data_len = ntohs(p->ip4->length);

	p->data += p->header_len;
	p->data_len -= p->header_len;
	p->data_proto = p->ip4->proto;

	if (p->data_proto == 1) {
		if (p->ip4->flags_offset & htons(IP4_F_MASK | IP4_F_MF))
			return -1; /* fragmented ICMP is unsupported */
		if (p->data_len < sizeof(struct icmp))
			return -1;
		p->icmp = (struct icmp *)(p->data);
	} else {
		if ((p->ip4->flags_offset & htons(IP4_F_MF)) &&
				(p->data_len & 0x7))
			return -1;

		if ((uint32_t)((ntohs(p->ip4->flags_offset) & IP4_F_MASK) * 8) +
				p->data_len > 65535)
			return -1;
	}

	return 0;
}

/* Estimates the most likely MTU of the link that the datagram in question was
 * too large to fit through, using the algorithm from RFC 1191. */
static unsigned int est_mtu(unsigned int too_big)
{
	static const unsigned int table[] = {
		65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 0
	};
	int i;

	for (i = 0; table[i]; ++i)
		if (too_big > table[i])
			return table[i];
	return 68;
}

static void xlate_4to6_icmp_error(struct pkt *p)
{
	struct {
		struct tun_pi pi;
		struct ip6 ip6;
		struct icmp icmp;
		struct ip6 ip6_em;
	} __attribute__ ((__packed__)) header;
	struct iovec iov[2];
	struct pkt p_em;
	uint32_t mtu;
	uint16_t em_len;
	struct cache_entry *orig_dest = NULL;

	memset(&p_em, 0, sizeof(p_em));
	p_em.data = p->data + sizeof(struct icmp);
	p_em.data_len = p->data_len - sizeof(struct icmp);

	if (p->icmp->type == 3 || p->icmp->type == 11 || p->icmp->type == 12) {
		em_len = (ntohl(p->icmp->word) >> 14) & 0x3fc;
		if (em_len) {
			if (p_em.data_len < em_len) {
				slog(LOG_DEBUG,"em packet length error %s:%d\n",__FUNCTION__,__LINE__);
				return;
			}
			p_em.data_len = em_len;
		}
	}

	if (parse_ip4(&p_em) < 0) {
		slog(LOG_DEBUG,"Falied to parse em as ip4 %s:%d\n",__FUNCTION__,__LINE__);
		return;
	}

	if (p_em.data_proto == 1 && p_em.icmp->type != 8) {
		slog(LOG_DEBUG,"Dropping packet since it's ICMP and not Ping %s:%d\n",__FUNCTION__,__LINE__);
		return;
	}

	if (sizeof(struct ip6) * 2 + sizeof(struct icmp) + p_em.data_len > 1280)
		p_em.data_len = 1280 - sizeof(struct ip6) * 2 -
						sizeof(struct icmp);

	if (map_ip4_to_ip6(&header.ip6_em.src, &p_em.ip4->src, NULL) ||
			map_ip4_to_ip6(&header.ip6_em.dest,
					&p_em.ip4->dest, &orig_dest)) {
		slog(LOG_DEBUG,"Failed to map em src or dest %s:%d\n",__FUNCTION__,__LINE__);
		return;
	}

	xlate_header_4to6(&p_em, &header.ip6_em,
				ntohs(p_em.ip4->length) - p_em.header_len);

	switch (p->icmp->type) {
	case 3: /* Destination Unreachable */
		header.icmp.type = 1; /* Destination Unreachable */
		header.icmp.word = 0;
		switch (p->icmp->code) {
		case 0: /* Network Unreachable */
			dummy();
		case 1: /* Host Unreachable */
			dummy();
		case 5: /* Source Route Failed */
			dummy();
		case 6:
			dummy();
		case 7:
			dummy();
		case 8:
			dummy();
		case 11:
			dummy();
		case 12:
			header.icmp.code = 0; /* No route to destination */
			break;
		case 2: /* Protocol Unreachable */
			header.icmp.type = 4;
			header.icmp.code = 1;
			header.icmp.word = htonl(6);
			break;
		case 3: /* Port Unreachable */
			header.icmp.code = 4; /* Port Unreachable */
			break;
		case 4: /* Fragmentation needed and DF set */
			header.icmp.type = 2;
			header.icmp.code = 0;
			mtu = ntohl(p->icmp->word) & 0xffff;
			if (mtu < 68)
				mtu = est_mtu(ntohs(p_em.ip4->length));
			mtu += MTU_ADJ;
			if (mtu > gcfg.mtu)
				mtu = gcfg.mtu;
			if (mtu < 1280 && gcfg.allow_ident_gen && orig_dest) {
				orig_dest->flags |= CACHE_F_GEN_IDENT;
				mtu = 1280;
			}
			header.icmp.word = htonl(mtu);
			break;
		case 9:
			dummy();
		case 10:
			dummy();
		case 13:
			dummy();
		case 15:
			header.icmp.code = 1; /* Administratively prohibited */
			break;
		default:
			slog(LOG_DEBUG,"Hit default case in %s:%d (ICMP Dest Unreach)\n",__FUNCTION__,__LINE__);
			return;
		}
		break;
	case 11: /* Time Exceeded */
		header.icmp.type = 3; /* Time Exceeded */
		header.icmp.code = p->icmp->code;
		header.icmp.word = 0;
		break;
	case 12: /* Parameter Problem */
		if (p->icmp->code != 0 && p->icmp->code != 2) {
			slog(LOG_DEBUG,"Drop packet due to parameter problem at %s:%d\n",__FUNCTION__,__LINE__);
			return;
		}
		static const int32_t new_ptr_tbl[] = {0,1,4,4,-1,-1,-1,-1,7,6,-1,-1,8,8,8,8,24,24,24,24};
		int32_t old_ptr = (ntohl(p->icmp->word) >> 24);
		if(old_ptr > 19) {
			slog(LOG_DEBUG,"Drop packet due to parameter problem - invalid pointer at %s:%d\n",__FUNCTION__,__LINE__);
			return;
		}
		if(new_ptr_tbl[old_ptr] < 0) {
			slog(LOG_DEBUG,"Drop packet due to parameter problem, not translatable\n");
			return;
		}
		header.icmp.type = 4;
		header.icmp.code = 0;
		header.icmp.word = htonl(new_ptr_tbl[old_ptr]);
		break;
	default:
		slog(LOG_DEBUG,"Hit default case in %s:%d (ICMP Type)\n",__FUNCTION__,__LINE__);
		return;
	}

	if (xlate_payload_4to6(&p_em, &header.ip6_em) < 0) {
		slog(LOG_DEBUG,"xlate_payload_4to6 failed at %s:%d\n",__FUNCTION__,__LINE__);
		return;
	}

	if (map_ip4_to_ip6(&header.ip6.src, &p->ip4->src, NULL)) {
		char temp[64];
		slog(LOG_DEBUG,"Needed to rely on fake source for ip4 %s\n",
			inet_ntop(AF_INET,&p->ip4->src,temp,64));
		//Fake source IP is our own IP
		header.ip6.src = gcfg.local_addr6;
	}

	if (map_ip4_to_ip6(&header.ip6.dest, &p->ip4->dest, NULL)) {
		slog(LOG_DEBUG,"map_ip4_to_ip6 failed at %s:%d\n",__FUNCTION__,__LINE__);
		return;
	}

	xlate_header_4to6(p, &header.ip6,
		sizeof(header.icmp) + sizeof(header.ip6_em) + p_em.data_len);
	--header.ip6.hop_limit;

	header.icmp.cksum = 0;
	header.icmp.cksum = ones_add(ip6_checksum(&header.ip6,
					ntohs(header.ip6.payload_length), 58),
			ones_add(ip_checksum(&header.icmp,
						sizeof(header.icmp) +
						sizeof(header.ip6_em)),
				ip_checksum(p_em.data, p_em.data_len)));

	TUN_SET_PROTO(&header.pi,  ETH_P_IPV6);

	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = p_em.data;
	iov[1].iov_len = p_em.data_len;

	if (writev(gcfg.tun_fd, iov, 2) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(errno));
}

void handle_ip4(struct pkt *p)
{
	if (parse_ip4(p) < 0 || p->ip4->ttl == 0 ||
			ip_checksum(p->ip4, p->header_len) ||
			p->header_len + p->data_len != ntohs(p->ip4->length))
		return;

	if (p->icmp && ip_checksum(p->data, p->data_len))
		return;

	if (p->ip4->dest.s_addr == gcfg.local_addr4.s_addr) {
		if (p->data_proto == 1)
			host_handle_icmp4(p);
		else
			host_send_icmp4_error(3, 2, 0, p);
	} else {
		if (p->ip4->ttl == 1) {
			host_send_icmp4_error(11, 0, 0, p);
			return;
		}
		if (p->data_proto != 1 || p->icmp->type == 8 ||
				p->icmp->type == 0)
			xlate_4to6_data(p);
		else
			xlate_4to6_icmp_error(p);
	}
}

static void host_send_icmp6(uint8_t tc, struct in6_addr *src,
		struct in6_addr *dest, struct icmp *icmp,
		uint8_t *data, int data_len)
{
	struct {
		struct tun_pi pi;
		struct ip6 ip6;
		struct icmp icmp;
	} __attribute__ ((__packed__)) header;
	struct iovec iov[2];

	TUN_SET_PROTO(&header.pi,  ETH_P_IPV6);
	header.ip6.ver_tc_fl = htonl((0x6 << 28) | (tc << 20));
	header.ip6.payload_length = htons(sizeof(header.icmp) + data_len);
	header.ip6.next_header = 58;
	header.ip6.hop_limit = 64;
	header.ip6.src = *src;
	header.ip6.dest = *dest;
	header.icmp = *icmp;
	header.icmp.cksum = 0;
	header.icmp.cksum = ones_add(ip_checksum(data, data_len),
			ip_checksum(&header.icmp, sizeof(header.icmp)));
	header.icmp.cksum = ones_add(header.icmp.cksum,
			ip6_checksum(&header.ip6,
					data_len + sizeof(header.icmp), 58));
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = data;
	iov[1].iov_len = data_len;
	if (writev(gcfg.tun_fd, iov, data_len ? 2 : 1) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(errno));
}

static void host_send_icmp6_error(uint8_t type, uint8_t code, uint32_t word,
				struct pkt *orig)
{
	struct icmp icmp;
	int orig_len;

	/* Don't send ICMP errors in response to ICMP messages other than
	   echo request */
	if (orig->data_proto == 58 && orig->icmp->type != 128)
		return;

	orig_len = sizeof(struct ip6) + orig->header_len + orig->data_len;
	if (orig_len > 1280 - sizeof(struct ip6) - sizeof(struct icmp))
		orig_len = 1280 - sizeof(struct ip6) - sizeof(struct icmp);
	icmp.type = type;
	icmp.code = code;
	icmp.word = htonl(word);
	host_send_icmp6(0, &gcfg.local_addr6, &orig->ip6->src, &icmp,
			(uint8_t *)orig->ip6, orig_len);
}

static void host_handle_icmp6(struct pkt *p)
{
	p->data += sizeof(struct icmp);
	p->data_len -= sizeof(struct icmp);

	switch (p->icmp->type) {
	case 128:
		p->icmp->type = 129;
		host_send_icmp6((ntohl(p->ip6->ver_tc_fl) >> 20) & 0xff,
				&p->ip6->dest, &p->ip6->src,
				p->icmp, p->data, p->data_len);
		break;
	}
}

static int xlate_6to4_header(struct pkt *p, int em)
{
	int ret;
	slog(LOG_DEBUG,"about to map src\n");

	/* Perform v6 to v4 address mapping for source
	 * No dynamic allow if we are em
	 * No dynamic alloc if we are an ICMP Error
	 * otherwise, allow dynamic alloc
	 */
	int dyn = (em ? 0 : (p->icmp && p->icmp->type < 128) ? 0 : 1);
	ret = map_ip6_to_ip4(&p->ip4->src, &p->ip6->src, &p->src, dyn);	
	/* If we are doing an em header and got any error, drop packet
	 * If we are doing ICMP Error and get any error, use our own address
	 * Ref. RFC xxxx for this behavior
	 * If we got ERROR_DROP, then drop the packet
	 * If we got ERROR_REJECT, then kick back an ICMP Dest Unreach
		*/
	if((em && ret < ERROR_NONE)) {
		return ERROR_DROP;
	} else if(p->icmp && p->icmp->type < 128 && ret < ERROR_NONE) {
		char temp[64];
		slog(LOG_DEBUG,"%s:%d:Needed to rely on fake source for ip6 %s\n",
			__FUNCTION__,__LINE__,
			inet_ntop(AF_INET6,&p->ip6->src,temp,64));
		/* Our own IP4 */
		p->ip4->src = gcfg->local_addr4;
	} else if (ret == ERROR_DROP) {
		return ERROR_DROP;
	} else if (ret == ERROR_REJECT) {
		host_send_icmp6_error(1, 5, 0, p);
		return ERROR_DROP;
	}

	slog(LOG_DEBUG,"about to map dst\n");
	/* Perform v6 to v4 address mapping for destination, no dynamic alloc */
	ret = map_ip6_to_ip4(&p->ip4->dest, &p->ip6->dest, &p->dest, 0);
	/* Same error handling as above, without fake source */
	if((em && ret < ERROR_NONE) || (ret == ERROR_DROP)) {
		return ERROR_DROP;
	/* Not doing an em header and got reject */
	} else if (ret == ERROR_REJECT) {
		/* Kick back ICMP Dest Unreachable */
		host_send_icmp6_error(1, 0, 0, p);
		return ERROR_DROP;
	}
	slog(LOG_DEBUG,"about to xlate header\n");

	/* Translate v6 header to v4 header */
	p->ip4->ver_ihl = 0x45;
	p->ip4->tos = (ntohl(p->ip6->ver_tc_fl) >> 20) & 0xff;
	uint16_t temp_len = sizeof(struct ip4) + p->data_len;
	p->ip4->length = htons(temp_len);
	/* IPv6 header is a fragment */
	if (p->ip6_frag) {
		p->ip4->ident = htons(ntohl(p->ip6_frag->ident) & 0xffff);
		p->ip4->flags_offset =
			htons(ntohs(p->ip6_frag->offset_flags) >> 3);
		if (p->ip6_frag->offset_flags & htons(IP6_F_MF))
			p->ip4->flags_offset |= htons(IP4_F_MF);
	/* Not a fragment but we are generating IDs for this conn */
	} else if (p->dest && (p->dest->flags & CACHE_F_GEN_IDENT) &&
			p->header_len + p->data_len <= 1280) {
				p->ip4->ident = htons(p->dest->ip4_ident++);
				p->ip4->flags_offset = 0;
		if (p->dest->ip4_ident == 0)
			p->dest->ip4_ident++;
	/* Not a fragment and not generating IDs*/
	} else {
		p->ip4->ident = 0;
		/* Set DF for packets which were >1280 bytes as IPv6 */
		p->ip4->flags_offset = (temp_len > 1260) ? htons(IP4_F_DF) : 0;
	}
	p->ip4->ttl = p->ip6->hop_limit;
	p->ip4->proto = p->data_proto == 58 ? 1 : p->data_proto;
	p->ip4->cksum = 0;
	return ERROR_NONE;
}
/*
 * @brief Translate L4 checksum with given adjustment
 * 
 * @param p packet buffer
 * @param cksum checksum adjustment
 * @returns nonzero on error 
 */
static int xlate_6to4_payload(struct pkt *p,uint16_t cksum)
{
	uint16_t *tck;

	/* If this is a fragment, and not the first fragment (no l4 header) */
	if (p->ip6_frag && (p->ip6_frag->offset_flags & ntohs(IP6_F_MASK)))
		return ERROR_NONE;

	switch (p->data_proto) {
	/* UDP */
	case 17:
		if (p->data_len < 8)
			return ERROR_DROP; /* Not enough space for a UDP header */
		tck = (uint16_t *)(p->data + 6);
		if (!*tck)
			return ERROR_DROP; /* drop UDP packets with no checksum */
		break;
	/* TCP */
	case 6:
		if (p->data_len < 20)
			return ERROR_DROP; /* Not enough space for a TCP header */
		tck = (uint16_t *)(p->data + 16);
		break;
	/* ICMP is handled by another code path, and no other proto can be xlated */
	default:
		return ERROR_NONE;
	}
	*tck = ones_add(*tck, cksum);
	return ERROR_NONE;
}
/*
 * @brief Check IPv6 packet for hairpin conditions (RFC7757)
 *
 * Conditions to hairpin:
 * Destination was translated 6->4 using RFC6052 map (prefix)
 * Destination v4 is found in an EAM map (i.e. has non-RFC6052 v6 option)
 * Then, we need to translate the v6 dest to the EAM map entry (v6)
 * and translate the v6 src using RFC6052 so return packets come back
 * through the translator
 */
static int xlate_6to4_hairpin(struct pkt *p) 
{	
	/* New header buffer */
	struct {
		struct tun_pi pi;
		struct ip6 ip6;
	} new_hdr;
	int ret;
	uint16_t cksum;
	/* Check if destination has a cache, and that cache was RFC6052, not hairpin */
	if(p->dest && (p->dest->flags & CACHE_F_TYPE == MAP_TYPE_RFC6052)) return ERROR_NONE;
	
	slog(LOG_DEBUG,"First stage hairpin check\n");

	/* Attempt to map ip4 back into ip6 (fail if not possible) */
	struct cache_entry *xlate_dest;
	if(map_ip4_to_ip6(&new_hdr.ip6.dest, &p->ip4->dest, &xlate_dest)) return ERROR_NONE;

	slog(LOG_DEBUG,"Dest Type6 is %d, Type4 is %d, ip4 is %x\n",
		 p->dest->flags & CACHE_F_TYPE,
		 xlate_dest->flags & CACHE_F_TYPE,
		ntohl(p->ip4->dest.s_addr));
    
	/* To hairpin, must be either static or dynamic EAM hosts */
	if(((xlate_dest->flags & CACHE_F_TYPE) == MAP_TYPE_STATIC) ||
	   ((xlate_dest->flags & CACHE_F_TYPE) == MAP_TYPE_DYNAMIC_HOST)) {

		slog(LOG_DEBUG,"%s:%d:Got a packet which should hairpin\n",
			 __FUNCTION__,__LINE__);

		/* Initialize new ip6 to old ip6 header fields */
		new_hdr.ip6.ver_tc_fl = p->ip6->ver_tc_fl;
		new_hdr.ip6.hop_limit = p->ip6->hop_limit;

		/* Update Next Header + Len to either fragment or proto */
		if(p->ip6_frag) {
			new_hdr.ip6.next_header = 44;
			new_hdr.ip6.payload_length = htons(p->data_len + sizeof(struct ip6_frag));
		} else {
			new_hdr.ip6.next_header = p->data_proto;
			new_hdr.ip6.payload_length = htons(p->data_len);
		}

		/* Generate RFC6052-encoded source mapping */

		/* Generate ip6 psuedo-header checksum for new addresses */

		/* Update packet data checksum (drop packet if not possible) */
		if(xlate_6to4_payload(p,cksum)) return ERROR_DROP;

		/* Copy psuedo-header fields on top of original ip6 header */

		/* Check if packet was ICMPv6 and if we need to xlate em pkt */

		/* Transmit packet */
		struct iovec iov[3];
		int iov_idx = 0;
		iov[iov_idx].iov_base = &new_hdr;
		iov[iov_idx++].iov_len = sizeof(struct tun_pi) + sizeof(struct ip6);
		if(p->ip6_frag) {
			iov[iov_idx].iov_base = p->ip6_frag;
			iov[iov_idx++].iov_len = sizeof(struct ip6_frag);
		}
		iov[iov_idx].iov_base = p->data;
		iov[iov_idx++].iov_len = p->data_len;

		if (writev(gcfg->tun_fd, iov, iov_idx) < 0)
			slog(LOG_WARNING, "error writing packet to tun device: %s\n",
					strerror(errno));

		/* Drop processing of original pkt*/
		return ERROR_DROP;
	}
	/* Not hairpin, return no error */
	return ERROR_NONE;
}

static void xlate_6to4_data(struct pkt *p,struct new4 *new4)
{
	int ret;
	struct iovec iov[2];

	/* Packet came in too large */
	if (sizeof(struct ip6) + p->header_len + p->data_len > gcfg->mtu) {
		host_send_icmp6_error(2, 0, gcfg->mtu, p);
		return;
	}

	/* Update L4 payload checksums */
	if (xlate_6to4_payload(p, convert_cksum(p->ip6,p->ip4))) return;

	/* If ICMP, update types and checksums */
	if(p->data_proto == 58) {
		uint16_t cksum = ~ip6_checksum(p->ip6,htons(p->ip6->payload_length) - p->header_len,58);
		cksum = ones_add(p->icmp->cksum,cksum);
		p->data_proto = 1;
		if (p->icmp->type == 128) {
			p->icmp->type = 8;
			p->icmp->cksum = ones_add(cksum, 128 - 8);
		} else {
			p->icmp->type = 0;
			p->icmp->cksum = ones_add(cksum, 129 - 0);
		}	
	}

	/* Update cache seen flags */
	if (p->src) p->src->flags |= CACHE_F_SEEN_6TO4;
	if (p->dest) p->dest->flags |= CACHE_F_SEEN_6TO4;

	/* Compute new v4 checksum */
	p->ip4->cksum = ip_checksum(p->ip4, sizeof(struct ip4));

	/* Write to tun device */
	iov[0].iov_base = new4;
	iov[0].iov_len = sizeof(struct tun_pi) + sizeof(struct ip4);
	iov[1].iov_base = p->data;
	iov[1].iov_len = p->data_len;

	if (writev(gcfg.tun_fd, iov, 2) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(errno));
}

static int parse_ip6(struct pkt *p)
{
	int hdr_len;
	uint8_t seg_left = 0;
	uint16_t seg_ptr = sizeof(struct ip6);

	p->ip6 = (struct ip6 *)(p->data);

	/* Drop packet if any of the following true:
	 * Data length not long enough for a header
	 * Version field is not 6
	 * Either src or dest IP is not valid
	 */
	if (p->data_len < sizeof(struct ip6) ||
			(ntohl(p->ip6->ver_tc_fl) >> 28) != 6)
		return -1;

	/* Pointers to data field */
	p->data_proto = p->ip6->next_header;
	p->data += sizeof(struct ip6);
	p->data_len -= sizeof(struct ip6);

	/* Cap data_len to payload length */
	if (p->data_len > ntohs(p->ip6->payload_length))
		p->data_len = ntohs(p->ip6->payload_length);

	/* Strip extension header types 0, 43, 60 */
	while (p->data_proto == 0 ||   /* Hop-By-Hop Options */
		   p->data_proto == 43 ||  /* Routing */
		   p->data_proto == 60) {  /* Dest Options */
		/* Validate packet length against header */
		if (p->data_len < 2) return ERROR_DROP;
		hdr_len = (p->data[1] + 1) * 8;
		if (p->data_len < hdr_len) return ERROR_DROP;
		/* If it's a routing header, extract segments left 
		 * We will drop the packet, but need to finish parsing it first
		 */
		if(p->data_proto == 43) seg_left = p->data[3];
		if(!seg_left) seg_ptr += hdr_len;
		/* Extract next header from extension header */
		p->data_proto = p->data[0];
		p->data += hdr_len;
		p->data_len -= hdr_len;
		p->header_len += hdr_len;
	}

	/* Deal with fragment header type 44 */
	if (p->data_proto == 44) {
		/* Insufficient length for the header struct */
		if (p->ip6_frag || p->data_len < sizeof(struct ip6_frag))
			return ERROR_DROP;
		/* Unpack header struct */
		p->ip6_frag = (struct ip6_frag *)p->data;
		p->data_proto = p->ip6_frag->next_header;
		p->data += sizeof(struct ip6_frag);
		p->data_len -= sizeof(struct ip6_frag);
		p->header_len += sizeof(struct ip6_frag);

		if ((p->ip6_frag->offset_flags & htons(IP6_F_MF)) &&
				(p->data_len & 0x7))
			return ERROR_DROP; /* TBD should be ICMP? */

		if ((uint32_t)(ntohs(p->ip6_frag->offset_flags) & IP6_F_MASK) +
				p->data_len > 65535)
			return ERROR_DROP; /* TBD should be ICMP? */
	}

	/* If ICMP, validate it's not fragmented and store pointer */
	if (p->data_proto == 58) {
		/* Fragment ICMP not supported */
		if (p->ip6_frag && (p->ip6_frag->offset_flags &
					htons(IP6_F_MASK | IP6_F_MF)))
			return ERROR_DROP;
		/* Validate data length for ICMP header */
		if (p->data_len < sizeof(struct icmp))
			return ERROR_DROP;
		p->icmp = (struct icmp *)(p->data);
	}

	/* IF we got a routing header with segments left
	 * kick back a Parameter Problem pointing to the seg field
	 */
	if(seg_left) {
		seg_ptr += 4;
		slog(LOG_DEBUG,"%s:%d:IPv6 Routing Header w/ Segments Left ptr=%d\n", 
			 __FUNCTION__,__LINE__,seg_ptr);
		host_send_icmp6_error(4, 0, seg_ptr, p);
		return ERROR_DROP;
	}
	return ERROR_NONE;
}

static void xlate_6to4_icmp_error(struct pkt *p,struct new4 *new4)
{
	struct iovec iov[2];
	struct pkt p_em;
	uint32_t mtu;
	uint16_t em_len;

	/* New pkt for the embedded packet */
	memset(&p_em, 0, sizeof(p_em));
	p_em.data = p->data + sizeof(struct icmp);
	p_em.data_len = p->data_len - sizeof(struct icmp);

	/* Get embedded length from icmp header word (only some types) */
	if (p->icmp->type == 1 || p->icmp->type == 3) {
		em_len = (ntohl(p->icmp->word) >> 21) & 0x7f8;
		if (em_len) {
			if (p_em.data_len < em_len)
				return;
			p_em.data_len = em_len;
		}
	}

	/* Parse em header */
	if (parse_ip6(&p_em)) return;

	/* Don't allow nested ICMP errors */
	if (p_em.data_proto == 58 && p_em.icmp->type != 128) return;

	/* Limit payload length to 576 bytes including both headers */
	if (sizeof(struct ip4) * 2 + sizeof(struct icmp) + p_em.data_len > 576)
		p_em.data_len = 576 - sizeof(struct ip4) * 2 -
						sizeof(struct icmp);

	/* Translate ICMP Type / Code */
	switch (p->icmp->type) {
	case 1: /* Destination Unreachable */
		new4->icmp.type = 3; /* Destination Unreachable */
		new4->icmp.word = 0;
		switch (p->icmp->code) {
		case 0: /* No route to destination */
		dummy();
		case 2: /* Beyond scope of source address */
		dummy();
		case 3: /* Address Unreachable */
			new4->icmp.code = 1; /* Host Unreachable */
			break;
		case 1: /* Administratively prohibited */
			new4->icmp.code = 10; /* Administratively prohibited */
			break;
		case 4: /* Port Unreachable */
			new4->icmp.code = 3; /* Port Unreachable */
			break;
		default:
			slog(LOG_DEBUG,"%s:%d:Unknown Type 1 Code %d\n", 
				 __FUNCTION__,__LINE__,p->icmp->code);
			return;
		}
		break;
	case 2: /* Packet Too Big */
		new4->icmp.type = 3; /* Destination Unreachable */
		new4->icmp.code = 4; /* Fragmentation needed */
		mtu = ntohl(p->icmp->word);
		if (mtu < 68) {
			slog(LOG_INFO, "%s:%d:no mtu in Packet Too Big message\n",
			 	 __FUNCTION__,__LINE__);
			return;
		}
		if (mtu > gcfg.mtu)
			mtu = gcfg.mtu;
		mtu -= MTU_ADJ;
		new4->icmp.word = htonl(mtu);
		break;
	case 3: /* Time Exceeded */
		new4->icmp.type = 11; /* Time Exceeded */
		new4->icmp.code = p->icmp->code;
		new4->icmp.word = 0;
		break;
	case 4: /* Parameter Problem */
		/* Erroneous Header Field Encountered */
		if (p->icmp->code == 0) {
			static const int32_t new_ptr_tbl[] = {0,1,-1,-1,2,2,9,8};
			int32_t old_ptr = ntohl(p->icmp->word);
			int32_t new_ptr;
			if(old_ptr > 39) {
				slog(LOG_DEBUG,"%s:%d:Drop packet due to parameter problem - invalid pointer\n",
					 __FUNCTION__,__LINE__);
				return;
			} else if(old_ptr > 23) {
				new_ptr = 16;
			} else if(old_ptr > 7) {
				new_ptr = 12;
			} else {
				new_ptr = new_ptr_tbl[old_ptr];
			}
			if(new_ptr < 0) {
				slog(LOG_DEBUG,"%s:%d:Drop packet due to parameter problem, not translatable\n",
					 __FUNCTION__,__LINE__);
				return;
			}
			new4->icmp.type = 12;
			new4->icmp.code = 0;
			new4->icmp.word = (htonl(new_ptr << 24));
			break;
		/* Unrecognized Next Header Type*/
		} else if (p->icmp->code == 1) {
			new4->icmp.type = 3; /* Destination Unreachable */
			new4->icmp.code = 2; /* Protocol Unreachable */
			new4->icmp.word = 0;
			break;
		}
		slog(LOG_DEBUG,"%s:%d:Unknown Type 4 Code %d\n",
			 __FUNCTION__,__LINE__,p->icmp->code);
		return;
	default:
		slog(LOG_DEBUG,"%s:%d:Unknown Type %d\n",
			 __FUNCTION__,__LINE__,p->icmp->type);
		return;
	}

	/* Translate embedded source, dest, and l4 headers */
	if (map_ip6_to_ip4(&new4->ip4_em.src, &p_em.ip6->src, NULL, 0)) {		
		slog(LOG_DEBUG, "%s:%d:Failed to translate em src\n",
			__FUNCTION__,__LINE__);
		return;
	} 
	if (map_ip6_to_ip4(&new4->ip4_em.dest, &p_em.ip6->dest, NULL, 0)) {		
		slog(LOG_DEBUG, "%s:%d:Failed to translate em dest\n",
			__FUNCTION__,__LINE__);
		return;
	}
	if (xlate_6to4_payload(&p_em, convert_cksum(p_em.ip6,&new4->ip4_em))) {		
		slog(LOG_DEBUG, "%s:%d:Failed to translate em l4\n",
			__FUNCTION__,__LINE__);
		return;
	}

	/* If em is ICMP, update types and checksums */
	if(p_em.data_proto == 58) {
		uint16_t cksum = ~ip6_checksum(p_em.ip6,htons(p_em.ip6->payload_length) - p_em.header_len,58);
		cksum = ones_add(p->icmp->cksum,cksum);
		p_em.data_proto = 1;
		if (p_em.icmp->type == 128) {
			p_em.icmp->type = 8;
			p_em.icmp->cksum = ones_add(cksum, 128 - 8);
		} else {
			p_em.icmp->type = 0;
			p_em.icmp->cksum = ones_add(cksum, 129 - 0);
		}	
	}

	/* Translate em header */
	p_em.ip4 = &new4->ip4_em;
	xlate_6to4_header(&p_em, 1);

	/* Subtract 20 from new header, since we translated em header */
	p->ip4->length = htons(ntohs(p->ip4->length)-20);

	/* Calcualte em header checksum */
	new4->ip4_em.cksum = ip_checksum(&new4->ip4_em, sizeof(struct ip4));

	/* Calculate IP checksum of outer header */
	new4->ip4.cksum = ip_checksum(&new4->ip4, sizeof(struct ip4));

	xlate_header_6to4(&p_em, &header.ip4_em,
		ntohs(p_em.ip6->payload_length) - p_em.header_len, NULL);

	header.ip4_em.cksum =
		ip_checksum(&header.ip4_em, sizeof(header.ip4_em));

	//As this is an ICMP error packet, we will not further 
	//send errors, so treat return of REJECT = DROP
	if (map_ip6_to_ip4(&header.ip4.src, &p->ip6->src, NULL, 0)) {
		char temp[64];
		slog(LOG_DEBUG,"Needed to rely on fake source for ip6 %s\n",
			inet_ntop(AF_INET6,&p->ip6->src,temp,64));
		//fake source IP is our own IP
		header.ip4.src = gcfg.local_addr4;
	}

	if (map_ip6_to_ip4(&header.ip4.dest, &p->ip6->dest, NULL, 0))
		return;

	xlate_header_6to4(p, &header.ip4, sizeof(header.icmp) +
				sizeof(header.ip4_em) + p_em.data_len, NULL);
	--header.ip4.ttl;

	header.ip4.cksum = ip_checksum(&header.ip4, sizeof(header.ip4));

	/* Calculate updated ICMP checksum */
	new4->icmp.cksum = 0;
	new4->icmp.cksum = ones_add(ip_checksum(&new4->icmp,
							sizeof(struct icmp) +
							sizeof(struct ip4)),
				ip_checksum(p_em.data, p_em.data_len));

	/* Transmit packet */
	iov[0].iov_base = new4;
	iov[0].iov_len = sizeof(struct new4);
	iov[1].iov_base = p_em.data;
	iov[1].iov_len = p_em.data_len;

	if (writev(gcfg.tun_fd, iov, 2) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(errno));
}

void handle_ip6(struct pkt *p)
{
	/* Parse IPv6 Header into pkt p */
	if (parse_ip6(p) < 0 || p->ip6->hop_limit == 0 ||
			p->header_len + p->data_len !=
				ntohs(p->ip6->payload_length))
		return; /* Packet falls on the ground */

	/* If packet is ICMP, check the checksum is valid (zero) */
	if (p->icmp && ones_add(ip_checksum(p->data, p->data_len),
				ip6_checksum(p->ip6, p->data_len, 58)))
		return; /* Packet falls on the ground */

	/* If packet destination is our own IPv6, handle it */
	if (IN6_ARE_ADDR_EQUAL(&p->ip6->dest, &gcfg.local_addr6)) {
		/* Handle ICMPv6 to ourselves */
		if (p->data_proto == 58)
			host_handle_icmp6(p);
		/* Kick back ICMP error, we can't handle anything else */
		else
			host_send_icmp6_error(4, 1, 6, p);
		return;
	}
	
	/* Kick back ICMP Time Exceeded if hop limit has reached 1 */
	if (p->ip6->hop_limit == 1) {
		host_send_icmp6_error(3, 0, 0, p);
		return;
	}
	/* Decrement hop limit */
	p->ip6->hop_limit--;

	/* Space for result packet */
	struct new4 new4;
	TUN_SET_PROTO(&new4.pi,ETH_P_IP);
	p->ip4 = &new4.ip4;

	/* Translate packet header v6->v4 */
	if(xlate_6to4_header(p, 0)) return;

	/* Check for and handle hairpin packets */
	if(xlate_6to4_hairpin(p)) return;

	/* Translate data or icmp non-error */
	if (p->data_proto != 58 ||
		p->icmp->type == 128 ||
		p->icmp->type == 129) {
		xlate_6to4_data(p,&new4);
	/* Translate ICMP error */
	} else xlate_6to4_icmp_error(p,&new4);

}
