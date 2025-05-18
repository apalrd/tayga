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

extern struct config *gcfg;

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
	if (writev(gcfg->tun_fd, iov, data_len ? 2 : 1) < 0)
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
	host_send_icmp4(0, &gcfg->local_addr4, &orig->ip4->src, &icmp,
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

	frag_size = gcfg->ipv6_offlink_mtu;
	if (frag_size > gcfg->mtu)
		frag_size = gcfg->mtu;
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
			if (gcfg->mtu - MTU_ADJ < p->header_len + p->data_len) {
				host_send_icmp4_error(3, 4,
						gcfg->mtu - MTU_ADJ, p);
				return;
			}
			no_frag_hdr = 1;
		} else if (gcfg->lazy_frag_hdr && p->data_len <= frag_size) {
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

		if (writev(gcfg->tun_fd, iov, 2) < 0)
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

			if (writev(gcfg->tun_fd, iov, 2) < 0) {
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
	int allow_fake_source = 0;
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
			allow_fake_source = 1;
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
			if (mtu > gcfg->mtu)
				mtu = gcfg->mtu;
			if (mtu < 1280 && gcfg->allow_ident_gen && orig_dest) {
				orig_dest->flags |= CACHE_F_GEN_IDENT;
				mtu = 1280;
			}
			header.icmp.word = htonl(mtu);
			allow_fake_source = 1;
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
		if (allow_fake_source)
			header.ip6.src = gcfg->local_addr6;
		else
			return;
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

	if (writev(gcfg->tun_fd, iov, 2) < 0)
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

	if (p->ip4->dest.s_addr == gcfg->local_addr4.s_addr) {
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
	if (writev(gcfg->tun_fd, iov, data_len ? 2 : 1) < 0)
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
	host_send_icmp6(0, &gcfg->local_addr6, &orig->ip6->src, &icmp,
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

static void xlate_header_6to4(struct pkt *p, struct ip4 *ip4,
		int payload_length, struct cache_entry *dest)
{
	ip4->ver_ihl = 0x45;
	ip4->tos = (ntohl(p->ip6->ver_tc_fl) >> 20) & 0xff;
	ip4->length = htons(sizeof(struct ip4) + payload_length);
	if (p->ip6_frag) {
		ip4->ident = htons(ntohl(p->ip6_frag->ident) & 0xffff);
		ip4->flags_offset =
			htons(ntohs(p->ip6_frag->offset_flags) >> 3);
		if (p->ip6_frag->offset_flags & htons(IP6_F_MF))
			ip4->flags_offset |= htons(IP4_F_MF);
	} else if (dest && (dest->flags & CACHE_F_GEN_IDENT) &&
			p->header_len + payload_length <= 1280) {
		ip4->ident = htons(dest->ip4_ident++);
		ip4->flags_offset = 0;
		if (dest->ip4_ident == 0)
			dest->ip4_ident++;
	} else {
		ip4->ident = 0;
		ip4->flags_offset = htons(IP4_F_DF);
	}
	ip4->ttl = p->ip6->hop_limit;
	ip4->proto = p->data_proto == 58 ? 1 : p->data_proto;
	ip4->cksum = 0;
}

static int xlate_payload_6to4(struct pkt *p, struct ip4 *ip4)
{
	uint16_t *tck;
	uint16_t cksum;

	if (p->ip6_frag && (p->ip6_frag->offset_flags & ntohs(IP6_F_MASK)))
		return 0;

	switch (p->data_proto) {
	case 58:
		cksum = ~ip6_checksum(p->ip6, htons(p->ip6->payload_length) -
							p->header_len, 58);
		cksum = ones_add(p->icmp->cksum, cksum);
		if (p->icmp->type == 128) {
			p->icmp->type = 8;
			p->icmp->cksum = ones_add(cksum, 128 - 8);
		} else {
			p->icmp->type = 0;
			p->icmp->cksum = ones_add(cksum, 129 - 0);
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
	*tck = ones_add(*tck, convert_cksum(p->ip6, ip4));
	return 0;
}

static void xlate_6to4_data(struct pkt *p)
{
	struct {
		struct tun_pi pi;
		struct ip4 ip4;
	} __attribute__ ((__packed__)) header;
	struct cache_entry *src = NULL, *dest = NULL;
	int ret;
	struct iovec iov[2];

	ret = map_ip6_to_ip4(&header.ip4.dest, &p->ip6->dest, &dest, 0);
	if (ret == ERROR_REJECT) {
		host_send_icmp6_error(1, 0, 0, p);
		return;
	}
	else if (ret == ERROR_DROP){
		/* Drop packet */
		return;
	}

	ret = map_ip6_to_ip4(&header.ip4.src, &p->ip6->src, &src, 1);
	if (ret == ERROR_REJECT) {
		host_send_icmp6_error(1, 5, 0, p);
		return;
	}
	else if (ret == ERROR_DROP){
		/* Drop packet */
		return;
	}

	if (sizeof(struct ip6) + p->header_len + p->data_len > gcfg->mtu) {
		host_send_icmp6_error(2, 0, gcfg->mtu, p);
		return;
	}

	xlate_header_6to4(p, &header.ip4, p->data_len, dest);
	--header.ip4.ttl;

	if (xlate_payload_6to4(p, &header.ip4) < 0)
		return;

	if (src)
		src->flags |= CACHE_F_SEEN_6TO4;
	if (dest)
		dest->flags |= CACHE_F_SEEN_6TO4;

	TUN_SET_PROTO(&header.pi, ETH_P_IP);

	header.ip4.cksum = ip_checksum(&header.ip4, sizeof(header.ip4));

	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = p->data;
	iov[1].iov_len = p->data_len;

	if (writev(gcfg->tun_fd, iov, 2) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(errno));
}

static int parse_ip6(struct pkt *p)
{
	int hdr_len;

	p->ip6 = (struct ip6 *)(p->data);

	if (p->data_len < sizeof(struct ip6) ||
			(ntohl(p->ip6->ver_tc_fl) >> 28) != 6 ||
			validate_ip6_addr(&p->ip6->src) ||
			validate_ip6_addr(&p->ip6->dest))
		return -1;

	p->data_proto = p->ip6->next_header;
	p->data += sizeof(struct ip6);
	p->data_len -= sizeof(struct ip6);

	if (p->data_len > ntohs(p->ip6->payload_length))
		p->data_len = ntohs(p->ip6->payload_length);

	while (p->data_proto == 0 || p->data_proto == 43 ||
			p->data_proto == 60) {
		if (p->data_len < 2)
			return -1;
		hdr_len = (p->data[1] + 1) * 8;
		if (p->data_len < hdr_len)
			return -1;
		p->data_proto = p->data[0];
		p->data += hdr_len;
		p->data_len -= hdr_len;
		p->header_len += hdr_len;
	}

	if (p->data_proto == 44) {
		if (p->ip6_frag || p->data_len < sizeof(struct ip6_frag))
			return -1;
		p->ip6_frag = (struct ip6_frag *)p->data;
		p->data_proto = p->ip6_frag->next_header;
		p->data += sizeof(struct ip6_frag);
		p->data_len -= sizeof(struct ip6_frag);
		p->header_len += sizeof(struct ip6_frag);

		if ((p->ip6_frag->offset_flags & htons(IP6_F_MF)) &&
				(p->data_len & 0x7))
			return -1;

		if ((uint32_t)(ntohs(p->ip6_frag->offset_flags) & IP6_F_MASK) +
				p->data_len > 65535)
			return -1;
	}

	if (p->data_proto == 58) {
		if (p->ip6_frag && (p->ip6_frag->offset_flags &
					htons(IP6_F_MASK | IP6_F_MF)))
			return -1; /* fragmented ICMP is unsupported */
		if (p->data_len < sizeof(struct icmp))
			return -1;
		p->icmp = (struct icmp *)(p->data);
	}

	return 0;
}

static void xlate_6to4_icmp_error(struct pkt *p)
{
	struct {
		struct tun_pi pi;
		struct ip4 ip4;
		struct icmp icmp;
		struct ip4 ip4_em;
	} __attribute__ ((__packed__)) header;
	struct iovec iov[2];
	struct pkt p_em;
	uint32_t mtu;
	uint16_t em_len;
	int allow_fake_source = 0;

	memset(&p_em, 0, sizeof(p_em));
	p_em.data = p->data + sizeof(struct icmp);
	p_em.data_len = p->data_len - sizeof(struct icmp);

	if (p->icmp->type == 1 || p->icmp->type == 3) {
		em_len = (ntohl(p->icmp->word) >> 21) & 0x7f8;
		if (em_len) {
			if (p_em.data_len < em_len)
				return;
			p_em.data_len = em_len;
		}
	}

	if (parse_ip6(&p_em) < 0)
		return;

	if (p_em.data_proto == 58 && p_em.icmp->type != 128)
		return;

	if (sizeof(struct ip4) * 2 + sizeof(struct icmp) + p_em.data_len > 576)
		p_em.data_len = 576 - sizeof(struct ip4) * 2 -
						sizeof(struct icmp);

	switch (p->icmp->type) {
	case 1: /* Destination Unreachable */
		header.icmp.type = 3; /* Destination Unreachable */
		header.icmp.word = 0;
		switch (p->icmp->code) {
		case 0: /* No route to destination */
		dummy();
		case 2: /* Beyond scope of source address */
		dummy();
		case 3: /* Address Unreachable */
			header.icmp.code = 1; /* Host Unreachable */
			allow_fake_source = 1;
			break;
		case 1: /* Administratively prohibited */
			header.icmp.code = 10; /* Administratively prohibited */
			break;
		case 4: /* Port Unreachable */
			header.icmp.code = 3; /* Port Unreachable */
			break;
		default:
			return;
		}
		break;
	case 2: /* Packet Too Big */
		header.icmp.type = 3; /* Destination Unreachable */
		header.icmp.code = 4; /* Fragmentation needed */
		mtu = ntohl(p->icmp->word);
		if (mtu < 68) {
			slog(LOG_INFO, "no mtu in Packet Too Big message\n");
			return;
		}
		if (mtu > gcfg->mtu)
			mtu = gcfg->mtu;
		mtu -= MTU_ADJ;
		header.icmp.word = htonl(mtu);
		allow_fake_source = 1;
		break;
	case 3: /* Time Exceeded */
		header.icmp.type = 11; /* Time Exceeded */
		header.icmp.code = p->icmp->code;
		header.icmp.word = 0;
		break;
	case 4: /* Parameter Problem */
		/* Erroneous Header Field Encountered */
		if (p->icmp->code == 0) {
			static const int32_t new_ptr_tbl[] = {0,1,-1,-1,2,2,9,8};
			int32_t old_ptr = ntohl(p->icmp->word);
			int32_t new_ptr;
			if(old_ptr > 39) {
				slog(LOG_DEBUG,"Drop packet due to parameter problem - invalid pointer at %s:%d\n",__FUNCTION__,__LINE__);
				return;
			} else if(old_ptr > 23) {
				new_ptr = 16;
			} else if(old_ptr > 7) {
				new_ptr = 12;
			} else {
				new_ptr = new_ptr_tbl[old_ptr];
			}
			if(new_ptr < 0) {
				slog(LOG_DEBUG,"Drop packet due to parameter problem, not translatable\n");
				return;
			}
			header.icmp.type = 12;
			header.icmp.code = 0;
			header.icmp.word = (htonl(new_ptr << 24));
			break;
		/* Unrecognized Next Header Type*/
		} else if (p->icmp->code == 1) {
			header.icmp.type = 3; /* Destination Unreachable */
			header.icmp.code = 2; /* Protocol Unreachable */
			header.icmp.word = 0;
			break;
		}
		slog(LOG_DEBUG,"Dropping unknown ICMPv6 parameter problem packet\n");
		return;
	default:
		return;
	}

	if (map_ip6_to_ip4(&header.ip4_em.src, &p_em.ip6->src, NULL, 0) ||
			map_ip6_to_ip4(&header.ip4_em.dest,
						&p_em.ip6->dest, NULL, 0) ||
			xlate_payload_6to4(&p_em, &header.ip4_em) < 0)
		return;

	xlate_header_6to4(&p_em, &header.ip4_em,
		ntohs(p_em.ip6->payload_length) - p_em.header_len, NULL);

	header.ip4_em.cksum =
		ip_checksum(&header.ip4_em, sizeof(header.ip4_em));

	if (map_ip6_to_ip4(&header.ip4.src, &p->ip6->src, NULL, 0)) {
		char temp[64];
		slog(LOG_DEBUG,"Needed to rely on fake source for ip6 %s\n",
			inet_ntop(AF_INET6,&p->ip6->src,temp,64));
		if (allow_fake_source)
			header.ip4.src = gcfg->local_addr4;
		else
			return;
	}

	if (map_ip6_to_ip4(&header.ip4.dest, &p->ip6->dest, NULL, 0))
		return;

	xlate_header_6to4(p, &header.ip4, sizeof(header.icmp) +
				sizeof(header.ip4_em) + p_em.data_len, NULL);
	--header.ip4.ttl;

	header.ip4.cksum = ip_checksum(&header.ip4, sizeof(header.ip4));

	header.icmp.cksum = 0;
	header.icmp.cksum = ones_add(ip_checksum(&header.icmp,
							sizeof(header.icmp) +
							sizeof(header.ip4_em)),
				ip_checksum(p_em.data, p_em.data_len));

	TUN_SET_PROTO(&header.pi, ETH_P_IP);

	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = p_em.data;
	iov[1].iov_len = p_em.data_len;

	if (writev(gcfg->tun_fd, iov, 2) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
				strerror(errno));
}

void handle_ip6(struct pkt *p)
{
	if (parse_ip6(p) < 0 || p->ip6->hop_limit == 0 ||
			p->header_len + p->data_len !=
				ntohs(p->ip6->payload_length))
		return;

	if (p->icmp && ones_add(ip_checksum(p->data, p->data_len),
				ip6_checksum(p->ip6, p->data_len, 58)))
		return;

	if (IN6_ARE_ADDR_EQUAL(&p->ip6->dest, &gcfg->local_addr6)) {
		if (p->data_proto == 58)
			host_handle_icmp6(p);
		else
			host_send_icmp6_error(4, 1, 6, p);
	} else {
		if (p->ip6->hop_limit == 1) {
			host_send_icmp6_error(3, 0, 0, p);
			return;
		}

		if (p->data_proto != 58 || p->icmp->type == 128 ||
				p->icmp->type == 129)
			xlate_6to4_data(p);
		else
			xlate_6to4_icmp_error(p);
	}
}
