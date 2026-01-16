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
	ifr.ifr_flags = IFF_TUN;
#if WITH_MULTIQUEUE
	ifr.ifr_flags |= IFF_MULTI_QUEUE;
#endif
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

	/* Setup multiqueue additional queues */
#if WITH_MULTIQUEUE
	//slog(LOG_DEBUG,"Main tun fd is %d\n",gcfg->tun_fd);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_MULTI_QUEUE;
	strcpy(ifr.ifr_name, gcfg->tundev);
	for(int i = 0; i < gcfg->workers; i++) {
		gcfg->tun_fd_addl[i] = open("/dev/net/tun", O_RDWR);
		if (gcfg->tun_fd_addl[i] < 0) {
			slog(LOG_CRIT, "Unable to open /dev/net/tun, aborting: %s\n",
					strerror(errno));
			return ERROR_REJECT;
		}
		//slog(LOG_DEBUG,"Addl tun fd %d is %d\n",i,gcfg->tun_fd_addl[i]);
		if (ioctl(gcfg->tun_fd_addl[i], TUNSETIFF, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to attach tun device %s, aborting: "
					"%s\n", gcfg->tundev, strerror(errno));
			return ERROR_REJECT;
		}
		//slog(LOG_DEBUG,"Opened tun adapter for worker %d\n",i);
	}


	/* Disable queue of main tun if we have >0 workers */
	if(gcfg->workers > 0) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_DETACH_QUEUE;
		if(ioctl(gcfg->tun_fd, TUNSETQUEUE, (void *)&ifr)) slog(LOG_CRIT,"Unable to detach main queue\n");
	}

#endif

#if WITH_URING
	/* Initialize uring */
    if(io_uring_queue_init(MAX_QUEUE_DEPTH, &gcfg->ring, 0)) {
        fprintf(stderr, "Unable to setup io_uring: %s\n", strerror(errno));
        return ERROR_REJECT;
    }
#endif
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



int tun_read(uint8_t * recv_buf,int tun_fd)
{
	int ret;
	struct tun_pi *pi = (struct tun_pi *)(recv_buf+RECV_HEADER_OFFSET);
	struct pkt pbuf, *p = &pbuf;

	ret = read(tun_fd, recv_buf+RECV_HEADER_OFFSET, RECV_BUF_SIZE-RECV_HEADER_OFFSET);
	//slog(LOG_DEBUG,"Processing %d bytes from tun %d\n",ret,tun_fd);
	if (ret < 0) {
		if (errno == EAGAIN)
			return 0;
		slog(LOG_ERR, "received error when reading from tun "
				"device: %s\n", strerror(errno));
		return 0;
	}
	if ((size_t)ret < sizeof(struct tun_pi)) {
		slog(LOG_WARNING, "short read from tun device "
				"(%d bytes)\n", ret);
		return 0;
	}
	if ((uint32_t)ret == RECV_BUF_SIZE) {
		slog(LOG_WARNING, "dropping oversized packet\n");
		return 0;
	}
	memset(p, 0, sizeof(struct pkt));
	p->data = recv_buf + sizeof(struct tun_pi)+RECV_HEADER_OFFSET;
	p->data_len = ret - sizeof(struct tun_pi);
	switch (TUN_GET_PROTO(pi)) {
	case ETH_P_IP:
		handle_ip4(p);
		return ret - sizeof(struct tun_pi);
		break;
	case ETH_P_IPV6:
		handle_ip6(p);
		return ret - sizeof(struct tun_pi);
		break;
	default:
		slog(LOG_WARNING, "Dropping unknown proto %04x from "
				"tun device\n", ntohs(pi->proto));
		break;
	}
	return 0;
}