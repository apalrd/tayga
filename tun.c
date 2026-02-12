/*
 *  tun.c -- tunnel interface routines
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
#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

int netlink_wait_for_ack(int fd)
{
    char buf[4096];
    ssize_t len;
    struct nlmsghdr *nh;
	/* Receive ACK */
    len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
		slog(LOG_CRIT,"NETLINK Receive Failed\n");
        return ERROR_REJECT;
    }

    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
        if (nh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);

			//Found our ack
            if (err->error == 0) {
                close(fd);
                return 0;
            }
            close(fd);
			slog(LOG_CRIT,"NETLINK Returned Error %d\n",err->error);
            return ERROR_REJECT;
        }
    }

    close(fd);
	slog(LOG_CRIT,"NETLINK Response Not Received\n");
	return ERROR_REJECT;
}


/**
 * @brief Set interface flags via Netlink
 *
 * This function connects to the Netlink socket and sends a request to set
 * the specified flags on the given network interface.
 *
 * @param ifidx The index of the network interface (e.g., 0).
 * @param flags The flags to set on the interface (e.g., IFF_UP).
 * @param change The flags that are changing (e.g., IFF_UP).
 * @return 0 on success, ERROR_REJECT on failure.
 */
int netlink_set_if_flags(int ifidx,
                         unsigned int flags,
                         unsigned int change)
{
    int fd;
    struct {
        struct nlmsghdr nh;
        struct ifinfomsg ifi;
    } req;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
		slog(LOG_CRIT,"NETLINK Socket Failed\n");
        return ERROR_REJECT;
	}

    memset(&req, 0, sizeof(req));

    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_type  = RTM_NEWLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_seq   = 1;
    req.nh.nlmsg_pid   = getpid();

    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index  = ifidx;
    req.ifi.ifi_flags  = flags;
    req.ifi.ifi_change = change;

    if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
        close(fd);
		slog(LOG_CRIT,"NETLINK Send Failed\n");
        return ERROR_REJECT;
    }

    /* Receive ACK */
    return netlink_wait_for_ack(fd);
}

/**
 * @brief Modyfy interface address via Netlink
 * 
 * This function connects to the Netlink socket and sends a request to add or
 * delete an IP address on the specified network interface.
 * 
 * @param ifidx The index of the network interface
 * @param af_family The address family (e.g., AF_INET or AF_INET6
 * @param addr The IP address in in_addr or in6_addr format
 * @param prefixlen The prefix length of the IP address
 * @param add 1 to add or 0 to delete the address
 */
int netlink_addr_modify(int ifidx,
                        int af_family,
						const void *addr,
                        int prefixlen,
                        int add)
{
    int fd;
    char buf[256];
    struct nlmsghdr *nh;
    struct ifaddrmsg *ifa;
    struct rtattr *rta;
    size_t addrlen;


    if (af_family == AF_INET) addrlen = sizeof(struct in_addr);
    else addrlen = sizeof(struct in6_addr);

	/* Open socket */
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
		slog(LOG_CRIT,"NETLINK Socket Failed\n");
        return ERROR_REJECT;
	}

    memset(buf, 0, sizeof(buf));

	nh = (struct nlmsghdr *)buf;
    nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifa));
    nh->nlmsg_type  = add ? RTM_NEWADDR : RTM_DELADDR;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
                      (add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
    nh->nlmsg_seq   = 1;
    nh->nlmsg_pid   = getpid();

    ifa = NLMSG_DATA(nh);
    ifa->ifa_family    = af_family;
    ifa->ifa_prefixlen = prefixlen;
    ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
    ifa->ifa_index     = ifidx;

    /* IFA_ADDRESS */
    rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    rta->rta_type = IFA_ADDRESS;
    rta->rta_len  = RTA_LENGTH(addrlen);
    memcpy(RTA_DATA(rta), addr, addrlen);
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + rta->rta_len;

    /* IFA_LOCAL only meaningful for IPv4 */
    if (af_family == AF_INET) {
        rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
        rta->rta_type = IFA_LOCAL;
        rta->rta_len  = RTA_LENGTH(addrlen);
        memcpy(RTA_DATA(rta), addr, addrlen);
        nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + rta->rta_len;
    }

    if (send(fd, nh, nh->nlmsg_len, 0) < 0) {
        close(fd);
		slog(LOG_CRIT,"NETLINK Send Failed\n");
        return ERROR_REJECT;
    }

    /* Receive ACK */
    return netlink_wait_for_ack(fd);
}

/**
 * @brief Modyfy interface routes via Netlink
 * 
 * This function connects to the Netlink socket and sends a request to add or
 * delete a route to the specified network interface.
 * 
 * @param ifidx The index of the network interface
 * @param af_family The address family (e.g., AF_INET or AF_INET6
 * @param dst The route destination in in_addr or in6_addr format
 * @param prefixlen The prefix length of the route
 * @param add 1 to add or 0 to delete the route
 */
int netlink_route_dev_modify(int ifidx,
							 int af_family,
                             const void *dst,
                             int prefixlen,
                             int add)
{
    int fd;
	char buf[256];
    struct nlmsghdr *nh;
    struct rtmsg *rtm;
    struct rtattr *rta;
    size_t addrlen;

    if (af_family == AF_INET) addrlen = sizeof(struct in_addr);
    else addrlen = sizeof(struct in6_addr);

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
		slog(LOG_CRIT,"NETLINK Socket Failed\n");
        return ERROR_REJECT;
	}

    memset(buf, 0, sizeof(buf));

    /* Netlink header */
    nh = (struct nlmsghdr *)buf;
    nh->nlmsg_len   = NLMSG_LENGTH(sizeof(*rtm));
    nh->nlmsg_type  = add ? RTM_NEWROUTE : RTM_DELROUTE;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
                      (add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
    nh->nlmsg_seq   = 1;
    nh->nlmsg_pid   = getpid();

    /* Route message */
    rtm = NLMSG_DATA(nh);
    rtm->rtm_family   = af_family;
    rtm->rtm_table    = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_BOOT;
    rtm->rtm_scope    = RT_SCOPE_LINK;
    rtm->rtm_type     = RTN_UNICAST;
    rtm->rtm_dst_len  = prefixlen;

	/* Destination */
	rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
	rta->rta_type = RTA_DST;
	rta->rta_len  = RTA_LENGTH(addrlen);
	memcpy(RTA_DATA(rta), dst, addrlen);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + rta->rta_len;

    /* Output interface */
    rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    rta->rta_type = RTA_OIF;
    rta->rta_len  = RTA_LENGTH(sizeof(ifidx));
    memcpy(RTA_DATA(rta), &ifidx, sizeof(ifidx));
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + rta->rta_len;

    /* Send */
    if (send(fd, nh, nh->nlmsg_len, 0) < 0) {
        close(fd);
		slog(LOG_CRIT,"NETLINK Send Failed\n");
        return ERROR_REJECT;
    }

    /* Receive ACK */
	return netlink_wait_for_ack(fd);
}



int set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		slog(LOG_CRIT, "fcntl F_GETFL returned %s\n", strerror(errno));
		return ERROR_REJECT;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		slog(LOG_CRIT, "fcntl F_SETFL returned %s\n", strerror(errno));
		return ERROR_REJECT;
	}
    return 0;
}

#ifdef __linux__
int tun_setup(int do_mktun, int do_rmtun)
{
	struct ifreq ifr;
	int fd;

	gcfg->tun_fd = open("/dev/net/tun", O_RDWR);
	if (gcfg->tun_fd < 0) {
		slog(LOG_CRIT, "Unable to open /dev/net/tun, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_MULTI_QUEUE;
	strcpy(ifr.ifr_name, gcfg->tundev);
	if (ioctl(gcfg->tun_fd, TUNSETIFF, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to attach tun device %s, aborting: "
				"%s\n", gcfg->tundev, strerror(errno));
		return ERROR_REJECT;
	}

	if (do_mktun) {
		if (ioctl(gcfg->tun_fd, TUNSETPERSIST, 1) < 0) {
			slog(LOG_CRIT, "Unable to set persist flag on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
		if (ioctl(gcfg->tun_fd, TUNSETOWNER, 0) < 0) {
			slog(LOG_CRIT, "Unable to set owner on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
		if (ioctl(gcfg->tun_fd, TUNSETGROUP, 0) < 0) {
			slog(LOG_CRIT, "Unable to set group on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
		slog(LOG_NOTICE, "Created persistent tun device %s\n",
				gcfg->tundev);
		return 0;
	} else if (do_rmtun) {
		if (ioctl(gcfg->tun_fd, TUNSETPERSIST, 0) < 0) {
			slog(LOG_CRIT, "Unable to clear persist flag on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
		slog(LOG_NOTICE, "Removed persistent tun device %s\n",
				gcfg->tundev);
		return 0;
	}

	if(set_nonblock(gcfg->tun_fd)) return ERROR_REJECT;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		slog(LOG_CRIT, "Unable to create socket, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}

	/* Query MTU from tun adapter */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, gcfg->tundev);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to query MTU, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}
	close(fd);

	/* MTU is less than 1280, not allowed */
	gcfg->mtu = ifr.ifr_mtu;
	if(gcfg->mtu < MTU_MIN) {
		slog(LOG_CRIT, "MTU of %d is too small, must be at least %d\n",
				gcfg->mtu, MTU_MIN);
		return ERROR_REJECT;
	}

	slog(LOG_INFO, "Using tun device %s with MTU %d\n", gcfg->tundev,
			gcfg->mtu);

	/* Get our own device ID for the tun setup operations */
	int ifidx = if_nametoindex(gcfg->tundev);

    if (ifidx == 0) {
		slog(LOG_INFO, "Failed to get if idx from tun device %s\n",gcfg->tundev);
		return ERROR_REJECT;
    }
	/* Bring tun device up */
	if(gcfg->tun_up) {
		if(netlink_set_if_flags(ifidx,IFF_UP,IFF_UP)) return ERROR_REJECT;
		slog(LOG_INFO, "Tun device %s is UP\n",gcfg->tundev);
	}

	/* Add IPs to the tun dev */
	char addrbuf[64];
	struct list_head *entry;
	list_for_each(entry, &gcfg->tun_ip4_list) {
		struct tun_ip4 *ip4;
		ip4 = list_entry(entry, struct tun_ip4, list);
		if(netlink_addr_modify(ifidx,AF_INET,&ip4->addr,
				ip4->prefix_len,1)) return ERROR_REJECT;
		slog(LOG_INFO, "Added IPv4 address %s/%d to tun device %s\n",
			inet_ntop(AF_INET,&ip4->addr,addrbuf,64),
			ip4->prefix_len,gcfg->tundev);
	}
	list_for_each(entry, &gcfg->tun_ip6_list) {
		struct tun_ip6 *ip6;
		ip6 = list_entry(entry, struct tun_ip6, list);
		if(netlink_addr_modify(ifidx,AF_INET6,&ip6->addr,
				ip6->prefix_len,1)) return ERROR_REJECT;
		slog(LOG_INFO, "Added IPv6 address %s/%d to tun device %s\n",
			inet_ntop(AF_INET6,&ip6->addr,addrbuf,128),
			ip6->prefix_len,gcfg->tundev);
	}

	/* Add routes to the tun dev */
	list_for_each(entry, &gcfg->tun_rt4_list) {
		struct tun_ip4 *ip4;
		ip4 = list_entry(entry, struct tun_ip4, list);
		if(netlink_route_dev_modify(ifidx,AF_INET,&ip4->addr,
				ip4->prefix_len,1)) return ERROR_REJECT;
		slog(LOG_INFO, "Added IPv4 route %s/%d to tun device %s\n",
			inet_ntop(AF_INET,&ip4->addr,addrbuf,64),
			ip4->prefix_len,gcfg->tundev);
	}
	list_for_each(entry, &gcfg->tun_rt6_list) {
		struct tun_ip6 *ip6;
		ip6 = list_entry(entry, struct tun_ip6, list);
		if(netlink_route_dev_modify(ifidx,AF_INET6,&ip6->addr,
				ip6->prefix_len,1)) return ERROR_REJECT;
		slog(LOG_INFO, "Added IPv6 route %s/%d to tun device %s\n",
			inet_ntop(AF_INET6,&ip6->addr,addrbuf,128),
			ip6->prefix_len,gcfg->tundev);
	}

	/* Setup multiqueue additional queues */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_MULTI_QUEUE;
	strcpy(ifr.ifr_name, gcfg->tundev);
	for(int i = 0; i < gcfg->workers; i++) {
		gcfg->tun_fd_addl[i] = open("/dev/net/tun", O_RDWR);
		if (gcfg->tun_fd_addl[i] < 0) {
			slog(LOG_CRIT, "Unable to open /dev/net/tun, aborting: %s\n",
					strerror(errno));
			exit(1);
		}
		if (ioctl(gcfg->tun_fd_addl[i], TUNSETIFF, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to attach tun device %s, aborting: "
					"%s\n", gcfg->tundev, strerror(errno));
			exit(1);
		}
	}

	/* Disable queue of main tun if we have >0 workers */
	if(gcfg->workers > 0) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_DETACH_QUEUE;
		if(ioctl(gcfg->tun_fd, TUNSETQUEUE, (void *)&ifr)) slog(LOG_CRIT,"Unable to detach main queue\n");
	}

	//No error on setup
    return 0;
}
#endif /* ifdef __linux__ */

#ifdef __FreeBSD__
int tun_setup(int do_mktun, int do_rmtun)
{
	struct ifreq ifr;
	int fd, do_rename = 0, multi_af;
	char devname[64];

	if (strncmp(gcfg->tundev, "tun", 3))
		do_rename = 1;

	if ((do_mktun || do_rmtun) && do_rename)
	{
		slog(LOG_CRIT,
			"tunnel interface name needs to match tun[0-9]+ pattern "
				"for --mktun to work\n");
		return ERROR_REJECT;
	}

	snprintf(devname, sizeof(devname), "/dev/%s", do_rename ? "tun" : gcfg->tundev);

	gcfg->tun_fd = open(devname, O_RDWR);
	if (gcfg->tun_fd < 0) {
		slog(LOG_CRIT, "Unable to open %s, aborting: %s\n",
				devname, strerror(errno));
		return ERROR_REJECT;
	}

	if (do_mktun) {
		slog(LOG_NOTICE, "Created persistent tun device %s\n",
				gcfg->tundev);
		return;
	} else if (do_rmtun) {

		/* Close socket before removal */
		close(gcfg->tun_fd);

		fd = socket(PF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			slog(LOG_CRIT, "Unable to create control socket, aborting: %s\n",
					strerror(errno));
			return ERROR_REJECT;
		}

		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, gcfg->tundev);
		if (ioctl(fd, SIOCIFDESTROY, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to destroy interface %s, aborting: %s\n",
					gcfg->tundev, strerror(errno));
			return ERROR_REJECT;
		}

		close(fd);

		slog(LOG_NOTICE, "Removed persistent tun device %s\n",
				gcfg->tundev);
		return;
	}

	/* Set multi-AF mode */
	multi_af = 1;
	if (ioctl(gcfg->tun_fd, TUNSIFHEAD, &multi_af) < 0) {
			slog(LOG_CRIT, "Unable to set multi-AF on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			return ERROR_REJECT;
	}

	slog(LOG_CRIT, "Multi-AF mode set on %s\n", gcfg->tundev);

	if(set_nonblock(gcfg->tun_fd)) return ERROR_REJECT;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		slog(LOG_CRIT, "Unable to create socket, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}

	if (do_rename) {
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, fdevname(gcfg->tun_fd));
		ifr.ifr_data = gcfg->tundev;
		if (ioctl(fd, SIOCSIFNAME, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to rename interface %s to %s, aborting: %s\n",
					fdevname(gcfg->tun_fd), gcfg->tundev,
					strerror(errno));
			return ERROR_REJECT;
		}
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, gcfg->tundev);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to query MTU, aborting: %s\n",
				strerror(errno));
		return ERROR_REJECT;
	}
	close(fd);

	gcfg->mtu = ifr.ifr_mtu;

	slog(LOG_INFO, "Using tun device %s with MTU %d\n", gcfg->tundev,
			gcfg->mtu);
    return 0;
}
#endif


void tun_read(uint8_t * recv_buf,int tun_fd)
{
	int ret;
	struct tun_pi *pi = (struct tun_pi *)recv_buf;
	struct pkt pbuf, *p = &pbuf;

	ret = read(tun_fd, recv_buf, RECV_BUF_SIZE);
	if (ret < 0) {
		if (errno == EAGAIN)
			return;
		slog(LOG_ERR, "received error when reading from tun "
				"device: %s\n", strerror(errno));
		return;
	}
	if ((size_t)ret < sizeof(struct tun_pi)) {
		slog(LOG_WARNING, "short read from tun device "
				"(%d bytes)\n", ret);
		return;
	}
	if ((uint32_t)ret == RECV_BUF_SIZE) {
		slog(LOG_WARNING, "dropping oversized packet\n");
		return;
	}
	memset(p, 0, sizeof(struct pkt));
	p->data = recv_buf + sizeof(struct tun_pi);
	p->data_len = ret - sizeof(struct tun_pi);
	switch (TUN_GET_PROTO(pi)) {
	case ETH_P_IP:
		handle_ip4(p);
		break;
	case ETH_P_IPV6:
		handle_ip6(p);
		break;
	default:
		slog(LOG_WARNING, "Dropping unknown proto %04x from "
				"tun device\n", ntohs(pi->proto));
		break;
	}
}