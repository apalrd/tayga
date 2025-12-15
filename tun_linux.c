/*
 *  tun_linux.c -- tunnel interface optimizations for Linux
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
#ifdef __linux__


static void tun_setup(int do_mktun, int do_rmtun)
{
	struct ifreq ifr;
	int fd;

	gcfg->tun_fd = open("/dev/net/tun", O_RDWR);
	if (gcfg->tun_fd < 0) {
		slog(LOG_CRIT, "Unable to open /dev/net/tun, aborting: %s\n",
				strerror(errno));
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	strcpy(ifr.ifr_name, gcfg->tundev);
	if (ioctl(gcfg->tun_fd, TUNSETIFF, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to attach tun device %s, aborting: "
				"%s\n", gcfg->tundev, strerror(errno));
		exit(1);
	}

	if (do_mktun) {
		if (ioctl(gcfg->tun_fd, TUNSETPERSIST, 1) < 0) {
			slog(LOG_CRIT, "Unable to set persist flag on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			exit(1);
		}
		if (ioctl(gcfg->tun_fd, TUNSETOWNER, 0) < 0) {
			slog(LOG_CRIT, "Unable to set owner on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			exit(1);
		}
		if (ioctl(gcfg->tun_fd, TUNSETGROUP, 0) < 0) {
			slog(LOG_CRIT, "Unable to set group on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			exit(1);
		}
		slog(LOG_NOTICE, "Created persistent tun device %s\n",
				gcfg->tundev);
		return;
	} else if (do_rmtun) {
		if (ioctl(gcfg->tun_fd, TUNSETPERSIST, 0) < 0) {
			slog(LOG_CRIT, "Unable to clear persist flag on %s, "
					"aborting: %s\n", gcfg->tundev,
					strerror(errno));
			exit(1);
		}
		slog(LOG_NOTICE, "Removed persistent tun device %s\n",
				gcfg->tundev);
		return;
	}

	set_nonblock(gcfg->tun_fd);

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		slog(LOG_CRIT, "Unable to create socket, aborting: %s\n",
				strerror(errno));
		exit(1);
	}

	/* Query MTU from tun adapter */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, gcfg->tundev);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to query MTU, aborting: %s\n",
				strerror(errno));
		exit(1);
	}
	close(fd);

	/* MTU is less than 1280, not allowed */
	gcfg->mtu = ifr.ifr_mtu;
	if(gcfg->mtu < MTU_MIN) {
		slog(LOG_CRIT, "MTU of %d is too small, must be at least %d\n",
				gcfg->mtu, MTU_MIN);
		exit(1);
	}

	slog(LOG_INFO, "Using tun device %s with MTU %d\n", gcfg->tundev,
			gcfg->mtu);
}


#endif /* ifdef __linux__ */