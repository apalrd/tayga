/*
 *  tayga.c -- main server code
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
#include "version.h"

#include <stdarg.h>
#include <signal.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#define USAGE_TEXT	\
"TAYGA version %s\n" \
"Usage: %s [-c|--config CONFIGFILE] [-d] [-n|--nodetach] [-u|--user USERID]\n" \
"             [-g|--group GROUPID] [-r|--chroot] [-p|--pidfile PIDFILE]\n\n" \
"--config FILE      : Read configuration options from FILE\n" \
"-d                 : Enable debug messages (implies --nodetach)\n" \
"--nodetach         : Do not detach from terminal\n" \
"--user USERID      : Set uid to USERID after initialization\n" \
"--group GROUPID    : Set gid to GROUPID after initialization\n" \
"--chroot           : chroot() to data-dir (specified in config file)\n\n" \
"--pidfile FILE     : Write process ID of daemon to FILE\n"

extern struct config *gcfg;
time_t now;

static int signalfds[2];
static int use_stdout;

void slog(int priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	if (use_stdout)
		vprintf(format, ap);
	else if (priority != LOG_DEBUG)
		vsyslog(priority, format, ap);
	va_end(ap);
}

static void set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		slog(LOG_CRIT, "fcntl F_GETFL returned %s\n", strerror(errno));
		exit(1);
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		slog(LOG_CRIT, "fcntl F_SETFL returned %s\n", strerror(errno));
		exit(1);
	}
}

void read_random_bytes(void *d, int len)
{
	int ret;

	ret = read(gcfg->urandom_fd, d, len);
	if (ret < 0) {
		slog(LOG_CRIT, "read /dev/urandom returned %s\n",
				strerror(errno));
		exit(1);
	}
	if (ret < len) {
		slog(LOG_CRIT, "read /dev/urandom returned EOF\n");
		exit(1);
	}
}

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
#endif

#ifdef __FreeBSD__
static void tun_setup(int do_mktun, int do_rmtun)
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
		exit(1);
	}

	snprintf(devname, sizeof(devname), "/dev/%s", do_rename ? "tun" : gcfg->tundev);

	gcfg->tun_fd = open(devname, O_RDWR);
	if (gcfg->tun_fd < 0) {
		slog(LOG_CRIT, "Unable to open %s, aborting: %s\n",
				devname, strerror(errno));
		exit(1);
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
			exit(1);
		}

		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, gcfg->tundev);
		if (ioctl(fd, SIOCIFDESTROY, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to destroy interface %s, aborting: %s\n",
					gcfg->tundev, strerror(errno));
			exit(1);
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
			exit(1);
	}

	slog(LOG_CRIT, "Multi-AF mode set on %s\n", gcfg->tundev);

	set_nonblock(gcfg->tun_fd);

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		slog(LOG_CRIT, "Unable to create socket, aborting: %s\n",
				strerror(errno));
		exit(1);
	}

	if (do_rename) {
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, fdevname(gcfg->tun_fd));
		ifr.ifr_data = gcfg->tundev;
		if (ioctl(fd, SIOCSIFNAME, &ifr) < 0) {
			slog(LOG_CRIT, "Unable to rename interface %s to %s, aborting: %s\n",
					fdevname(gcfg->tun_fd), gcfg->tundev,
					strerror(errno));
			exit(1);
		}
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, gcfg->tundev);
	if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
		slog(LOG_CRIT, "Unable to query MTU, aborting: %s\n",
				strerror(errno));
		exit(1);
	}
	close(fd);

	gcfg->mtu = ifr.ifr_mtu;

	slog(LOG_INFO, "Using tun device %s with MTU %d\n", gcfg->tundev,
			gcfg->mtu);
}
#endif

static void signal_handler(int signal)
{
	(void)!write(signalfds[1], &signal, sizeof(signal));
}

static void signal_setup(void)
{
	struct sigaction act;

	if (pipe(signalfds) < 0) {
		slog(LOG_INFO, "unable to create signal pipe, aborting: %s\n",
				strerror(errno));
		exit(1);
	}
	set_nonblock(signalfds[0]);
	set_nonblock(signalfds[1]);
	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
}

static void read_from_tun(void)
{
	int ret;
	struct tun_pi *pi = (struct tun_pi *)gcfg->recv_buf;
	struct pkt pbuf, *p = &pbuf;

	ret = read(gcfg->tun_fd, gcfg->recv_buf, gcfg->recv_buf_size);
	if (ret < 0) {
		if (errno == EAGAIN)
			return;
		slog(LOG_ERR, "received error when reading from tun "
				"device: %s\n", strerror(errno));
		return;
	}
	if (ret < sizeof(struct tun_pi)) {
		slog(LOG_WARNING, "short read from tun device "
				"(%d bytes)\n", ret);
		return;
	}
	if (ret == gcfg->recv_buf_size) {
		slog(LOG_WARNING, "dropping oversized packet\n");
		return;
	}
	memset(p, 0, sizeof(struct pkt));
	p->data = gcfg->recv_buf + sizeof(struct tun_pi);
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

static void read_from_signalfd(void)
{
	int ret, sig;

	for (;;) {
		ret = read(signalfds[0], &sig, sizeof(sig));
		if (ret < 0) {
			if (errno == EAGAIN)
				return;
			slog(LOG_CRIT, "got error %s from signalfd\n",
					strerror(errno));
			exit(1);
		}
		if (ret == 0) {
			slog(LOG_CRIT, "signal fd was closed\n");
			exit(1);
		}
		if (gcfg->dynamic_pool)
			dynamic_maint(gcfg->dynamic_pool, 1);
		slog(LOG_NOTICE, "Exiting on signal %d\n", sig);
		exit(0);
	}
}

static void print_op_info(void)
{
	struct list_head *entry;
	struct map4 *s4;
	struct map6 *s6;
	struct map6 *m6;
	char addrbuf[64],addrbuf2[64];

	inet_ntop(AF_INET, &gcfg->local_addr4, addrbuf, sizeof(addrbuf));
	slog(LOG_INFO, "TAYGA's IPv4 address: %s\n", addrbuf);
	inet_ntop(AF_INET6, &gcfg->local_addr6, addrbuf, sizeof(addrbuf));
	slog(LOG_INFO, "TAYGA's IPv6 address: %s\n", addrbuf);
	m6 = list_entry(gcfg->map6_list.prev, struct map6, list);
	if (m6->type == MAP_TYPE_RFC6052) {
		inet_ntop(AF_INET6, &m6->addr, addrbuf, sizeof(addrbuf));
		slog(LOG_INFO, "NAT64 prefix: %s/%d\n",
				addrbuf, m6->prefix_len);
		if (m6->addr.s6_addr32[0] == WKPF
			&& !m6->addr.s6_addr32[1]
			&& !m6->addr.s6_addr32[2]
			&& gcfg->wkpf_strict)
			slog(LOG_NOTICE, "Note: traffic between IPv6 hosts and "
					"private IPv4 addresses (i.e. to/from "
					"64:ff9b::10.0.0.0/104, "
					"64:ff9b::192.168.0.0/112, etc) "
					"will be dropped.  Use a translation "
					"prefix within your organization's "
					"IPv6 address space instead of "
					"64:ff9b::/96 if you need your "
					"IPv6 hosts to communicate with "
					"private IPv4 addresses.\n");
	}
	if (gcfg->dynamic_pool) {
		inet_ntop(AF_INET, &gcfg->dynamic_pool->map4.addr,
				addrbuf, sizeof(addrbuf));
		slog(LOG_INFO, "Dynamic pool: %s/%d\n", addrbuf,
				gcfg->dynamic_pool->map4.prefix_len);
		if (gcfg->data_dir[0])
			load_dynamic(gcfg->dynamic_pool);
		else
			slog(LOG_NOTICE, "Note: dynamically-assigned mappings "
					"will not be saved across restarts.  "
					"Specify data-dir in config if you would "
					"like dynamic mappings to be "
					"persistent.\n");
	}

	slog(LOG_DEBUG,"Map4 List:\n");
	list_for_each(entry, &gcfg->map4_list) {
		s4 = list_entry(entry, struct map4, list);

		slog(LOG_DEBUG,"Entry %s/%d type %d mask %s\n",
			inet_ntop(AF_INET,&s4->addr,addrbuf,64),
			s4->prefix_len,s4->type,
			inet_ntop(AF_INET,&s4->mask,addrbuf2,64));
	}
	slog(LOG_DEBUG,"Map6 List:\n");
	list_for_each(entry, &gcfg->map6_list) {
		s6 = list_entry(entry, struct map6, list);

		slog(LOG_DEBUG,"Entry %s/%d type %d\n",
			inet_ntop(AF_INET6,&s6->addr,addrbuf,64),
			s6->prefix_len,s6->type);
	}
}

int main(int argc, char **argv)
{
	int c, ret, longind;
	int pidfd;
	struct pollfd pollfds[2];
	char addrbuf[INET6_ADDRSTRLEN];

	char *conffile = TAYGA_CONF_PATH;
	char *user = NULL;
	char *group = NULL;
	char *pidfile = NULL;
	int do_chroot = 0;
	int detach = 1;
	int do_mktun = 0;
	int do_rmtun = 0;
	struct passwd *pw = NULL;
	struct group *gr = NULL;

	/* Init config structure */
	if(config_init() < 0) return 1;

	static struct option longopts[] = {
		{ "mktun", 0, 0, 0 },
		{ "rmtun", 0, 0, 0 },
		{ "help", 0, 0, 0 },
		{ "config", 1, 0, 'c' },
		{ "nodetach", 0, 0, 'n' },
		{ "user", 1, 0, 'u' },
		{ "group", 1, 0, 'g' },
		{ "chroot", 0, 0, 'r' },
		{ "pidfile", 1, 0, 'p' },
		{ 0, 0, 0, 0 }
	};

	for (;;) {
		c = getopt_long(argc, argv, "c:dnu:g:rp:", longopts, &longind);
		if (c == -1)
			break;
		switch (c) {
		case 0:
			if (longind == 0) {
				if (do_rmtun) {
					fprintf(stderr, "Error: both --mktun "
						"and --rmtun specified.\n");
					exit(1);
				}
				do_mktun = 1;
			} else if (longind == 1) {
				if (do_mktun) {
					fprintf(stderr, "Error: both --mktun "
						"and --rmtun specified.\n");
					exit(1);
				}
				do_rmtun = 1;
			} else if (longind == 2) {
				fprintf(stderr, USAGE_TEXT, TAYGA_VERSION, argv[0]);
				exit(0);
			}
			break;
		case 'c':
			conffile = optarg;
			break;
		case 'd':
			use_stdout = 1;
			detach = 0;
			break;
		case 'n':
			detach = 0;
			break;
		case 'u':
			user = optarg;
			break;
		case 'g':
			group = optarg;
			break;
		case 'r':
			do_chroot = 1;
			break;
		case 'p':
			pidfile = optarg;
			break;
		default:
			fprintf(stderr, "Try `%s --help' for more "
					"information (got %c)\n", argv[0],c);
			exit(1);
		}
	}

	/* Parse config file options */
	if(config_read(conffile) < 0) return 1;

	/* Validate config */
	if(config_validate() < 0) return 1;

	/* Check if we are doing tunnel operations only */
	if (do_mktun || do_rmtun) {
		use_stdout = 1;
		if (user) {
			fprintf(stderr, "Error: cannot specify -u or --user "
					"with mktun/rmtun operation\n");
			exit(1);
		}
		if (group) {
			fprintf(stderr, "Error: cannot specify -g or --group "
					"with mktun/rmtun operation\n");
			exit(1);
		}
		if (do_chroot) {
			fprintf(stderr, "Error: cannot specify -r or --chroot "
					"with mktun/rmtun operation\n");
			exit(1);
		}
		tun_setup(do_mktun, do_rmtun);
		return 0;
	}

	/* Setup logging */
	if (!use_stdout)
		openlog("tayga", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/* Change user */
	if (user) {
		pw = getpwnam(user);
		if (!pw) {
			slog(LOG_CRIT, "Error: user %s does not exist\n", user);
			exit(1);
		}
	}

	/* Change group */
	if (group) {
		gr = getgrnam(group);
		if (!gr) {
			slog(LOG_CRIT, "Error: group %s does not exist\n",
					group);
			exit(1);
		}
	}

	/* Chroot */
	if (!gcfg->data_dir[0]) {
		if (do_chroot) {
			slog(LOG_CRIT, "Error: cannot chroot when no data-dir "
					"is specified in %s\n", conffile);
			exit(1);
		}
		if (chdir("/")) {
			slog(LOG_CRIT, "Error: unable to chdir to /, aborting: %s\n",
					strerror(errno));
			exit(1);
		}
	} else if (chdir(gcfg->data_dir) < 0) {
		if (user || errno != ENOENT) {
			slog(LOG_CRIT, "Error: unable to chdir to %s, "
					"aborting: %s\n", gcfg->data_dir,
					strerror(errno));
			exit(1);
		}
		if (mkdir(gcfg->data_dir, 0777) < 0) {
			slog(LOG_CRIT, "Error: unable to create %s, aborting: "
					"%s\n", gcfg->data_dir,
					strerror(errno));
			exit(1);
		}
		if (chdir(gcfg->data_dir) < 0) {
			slog(LOG_CRIT, "Error: created %s but unable to chdir "
					"to it!?? (%s)\n", gcfg->data_dir,
					strerror(errno));
			exit(1);
		}
	}

	if (do_chroot && (!pw || pw->pw_uid == 0)) {
		slog(LOG_CRIT, "Error: chroot is ineffective without also "
				"specifying the -u option to switch to an "
				"unprivileged user\n");
		exit(1);
	}

	if (pidfile) {
		pidfd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (pidfd < 0) {
			slog(LOG_CRIT, "Error, unable to open %s for "
					"writing: %s\n", pidfile,
					strerror(errno));
			exit(1);
		}
	}

	if (detach && daemon(1, 0) < 0) {
		slog(LOG_CRIT, "Error, unable to fork and detach: %s\n",
				strerror(errno));
		exit(1);
	}

	if (pidfile) {
		snprintf(addrbuf, sizeof(addrbuf), "%ld\n", (long)getpid());
		if (write(pidfd, addrbuf, strlen(addrbuf)) != strlen(addrbuf)) {
			slog(LOG_CRIT, "Error, unable to write PID file.\n");
			exit(1);
		}
		close(pidfd);
	}

	slog(LOG_INFO, "Starting TAYGA " TAYGA_VERSION "\n");
	slog(LOG_DEBUG, "Compiled from " TAYGA_BRANCH "\n");
	slog(LOG_DEBUG, "Commit " TAYGA_COMMIT "\n");

	if (gcfg->cache_size) {
		gcfg->urandom_fd = open("/dev/urandom", O_RDONLY);
		if (gcfg->urandom_fd < 0) {
			slog(LOG_CRIT, "Unable to open /dev/urandom, "
					"aborting: %s\n", strerror(errno));
			exit(1);
		}
		read_random_bytes(gcfg->rand, 8 * sizeof(uint32_t));
		gcfg->rand[0] |= 1; /* need an odd number for IPv4 hash */
	}

	tun_setup(0, 0);

	if (do_chroot) {
		if (chroot(gcfg->data_dir) < 0) {
			slog(LOG_CRIT, "Unable to chroot to %s: %s\n",
					gcfg->data_dir, strerror(errno));
			exit(1);
		}
		if (chdir("/")) {
			slog(LOG_CRIT, "Error: unable to chdir to /, aborting: %s\n",
					strerror(errno));
			exit(1);
		}
	}

	if (gr) {
		if (setregid(gr->gr_gid, gr->gr_gid) < 0 ||
				setregid(gr->gr_gid, gr->gr_gid) < 0 ||
				setgroups(1, &gr->gr_gid) < 0) {
			slog(LOG_CRIT, "Error: cannot set gid to %d: %s\n",
					gr->gr_gid, strerror(errno));
			exit(1);
		}
	}

	if (pw) {
		if (setreuid(pw->pw_uid, pw->pw_uid) < 0 ||
				setreuid(pw->pw_uid, pw->pw_uid) < 0) {
			slog(LOG_CRIT, "Error: cannot set uid to %d: %s\n",
					pw->pw_uid, strerror(errno));
			exit(1);
		}
	}

	signal_setup();

	/* Print running information */
	print_op_info();

	if (gcfg->cache_size)
		create_cache();

	gcfg->recv_buf = (uint8_t *)malloc(gcfg->recv_buf_size);
	if (!gcfg->recv_buf) {
		slog(LOG_CRIT, "Error: unable to allocate %d bytes for "
				"receive buffer\n", gcfg->recv_buf_size);
		exit(1);
	}

	memset(pollfds, 0, 2 * sizeof(struct pollfd));
	pollfds[0].fd = signalfds[0];
	pollfds[0].events = POLLIN;
	pollfds[1].fd = gcfg->tun_fd;
	pollfds[1].events = POLLIN;

	/* Main loop */
	for (;;) {
		ret = poll(pollfds, 2, POOL_CHECK_INTERVAL * 1000);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			slog(LOG_ERR, "poll returned error %s\n",
			strerror(errno));
			exit(1);
		}
		time(&now);
		if (pollfds[0].revents)
			read_from_signalfd();
		if (pollfds[1].revents)
			read_from_tun();
		if (gcfg->cache_size && (gcfg->last_cache_maint +
						CACHE_CHECK_INTERVAL < now ||
					gcfg->last_cache_maint > now)) {
			addrmap_maint();
			gcfg->last_cache_maint = now;
		}
		if (gcfg->dynamic_pool && (gcfg->last_dynamic_maint +
						POOL_CHECK_INTERVAL < now ||
					gcfg->last_dynamic_maint > now)) {
			dynamic_maint(gcfg->dynamic_pool, 0);
			gcfg->last_dynamic_maint = now;
		}
	}

	return 0;
}
