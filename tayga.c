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

#include <stdarg.h>
#include <signal.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

extern struct config *gcfg;
time_t now;
static const char *progname;
static int signalfds[2];

void usage(int code) {
	fprintf(stderr,
			"TAYGA version %s\n"
			"Usage:\n"
			"%s [-c|--config CONFIGFILE] [-d|--debug] [-n|--nodetach]\n"
			"       [-u|--user USERID] [-g|--group GROUPID] [-r|--chroot] [-p|--pidfile PIDFILE]\n"
			"       [--syslog|--stdout|--journal]\n"
			"%s --mktun [-c|--config CONFIGFILE]\n"
			"%s --rmtun [-c|--config CONFIGFILE]\n"
			"       [-u|--user USERID] [-g|--group GROUPID] [-r|--chroot] [-p|--pidfile PIDFILE]\n\n"
			"--config FILE      : Read configuration options from FILE\n"
			"--debug, -d        : Enable debug messages (implies --nodetach and --stdout)\n"
			"--nodetach         : Do not fork the process\n"
			"--syslog           : Log messages to syslog (default)\n"
			"--stdout           : Log messages to stdout\n"
			"--journal          : Log messages to the systemd journal\n"
			"--user USERID      : Set uid to USERID after initialization\n"
			"--group GROUPID    : Set gid to GROUPID after initialization\n"
			"--chroot           : chroot() to data-dir (specified in config file)\n"
			"--pidfile FILE     : Write process ID of daemon to FILE\n"
			"--mktun            : Create the persistent TUN interface\n"
			"--rmtun            : Remove the persistent TUN interface\n"
			"--help, -h         : Show this help message\n",
		TAYGA_VERSION, progname, progname, progname);
	exit(code);
}

/* Used during argument parsing, before logging is setup */
void die(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	putc('\n', stderr);
	exit(1);
}

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
	if(set_nonblock(signalfds[0])) exit(1);
	if(set_nonblock(signalfds[1])) exit(1);
	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
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
		if (gcfg->dynamic_pool) {
			pthread_mutex_lock(&gcfg->map_mutex);
			dynamic_maint(gcfg->dynamic_pool, 1);
			pthread_mutex_unlock(&gcfg->map_mutex);
		}
		slog(LOG_NOTICE, "Exiting on signal %d\n", sig);
		if (gcfg->log_out == LOG_TO_SYSLOG) {
			closelog();
		} else if (gcfg->log_out == LOG_TO_JOURNAL) {
			journal_cleanup();
		}
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
	slog(LOG_INFO, "tayga's IPv4 address: %s\n", addrbuf);
	inet_ntop(AF_INET6, &gcfg->local_addr6, addrbuf, sizeof(addrbuf));
	slog(LOG_INFO, "tayga's IPv6 address: %s\n", addrbuf);
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

/* Worker thread for multiqueue tun interface */
static void * worker(void * arg)
{
	int idx = *(int *)arg;
	uint8_t * recv_buf = (uint8_t *)malloc(RECV_BUF_SIZE);
	if (!recv_buf) {
		slog(LOG_CRIT, "Error: unable to allocate %d bytes for "
				"receive buffer\n", RECV_BUF_SIZE);
		exit(1);
	}

	/* Enter worker loop */
	slog(LOG_DEBUG,"Starting worker thread %d\n",idx);
	for (;;) {
		tun_read(recv_buf,gcfg->tun_fd_addl[idx]);
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
	progname = argv[0];

	/* Init config structure */
	if(config_init() < 0) return 1;

	static struct option longopts[] = {
		{ "mktun", 0, 0, 0 },
		{ "rmtun", 0, 0, 0 },
		{ "syslog", 0, 0, 0 },
		{ "stdout", 0, 0, 0 },
		{ "journal", 0, 0, 0 },
		{ "help", 0, 0, 'h' },
		{ "syslog", 0, 0, 0 },
		{ "stdout", 0, 0, 0 },
		{ "journal", 0, 0, 0 },
		{ "help", 0, 0, 'h' },
		{ "config", 1, 0, 'c' },
		{ "nodetach", 0, 0, 'n' },
		{ "user", 1, 0, 'u' },
		{ "group", 1, 0, 'g' },
		{ "chroot", 0, 0, 'r' },
		{ "pidfile", 1, 0, 'p' },
		{ "debug", 0, 0, 'd' },
		{ "debug", 0, 0, 'd' },
		{ 0, 0, 0, 0 }
	};

	/* Arg parsing loop */
	for (;;) {
		c = getopt_long(argc, argv, "c:dhnu:g:rp:", longopts, &longind);
		/* Reached last argument, terminate loop */
		if (c == -1)
			break;
		switch (c) {
		case 0:
			switch (longind) {
				case 0: /* --mktun */
					if (do_rmtun) {
						die("Error: both --mktun and --rmtun specified");
					}
					do_mktun = 1;
					break;
				case 1: /* --rmtun */
					if (do_mktun) {
						die("Error: both --mktun and --rmtun specified");
						exit(1);
					}
					do_rmtun = 1;
					break;
				case 2: /* --syslog */
					gcfg->log_out = LOG_TO_SYSLOG;
					break;
				case 3: /* --stdout */
					gcfg->log_out = LOG_TO_STDOUT;
					break;
				case 4: /* --journal */
					gcfg->log_out = LOG_TO_JOURNAL;
					break;
				default:
					usage(1);
			}
			break;
		case 'c':
			conffile = optarg;
			break;
		case 'd':
			gcfg->log_out = LOG_TO_STDOUT;
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
		case 'h':
			usage(1);
			break;
		default:
			die("Try `%s --help' for more information (got %c)", argv[0],c);
			exit(1);
		}
	}

	/* Setup logging
	 * But not if we are only doing mktun / rmtun
	 * This must be done before config parsing, since those rely
	 * on logging based on log_out
	 */
	if(do_mktun || do_rmtun) {
		//Force stdout for these options
		gcfg->log_out = LOG_TO_STDOUT;
	} else if (gcfg->log_out == LOG_TO_SYSLOG) {
		openlog("tayga", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	} else if (gcfg->log_out == LOG_TO_JOURNAL) {
		int r = journal_init("tayga");
		if (r < 0) {
			fprintf(stderr,"Error: Unable to initialize journal: %s\n", strerror(-r));
			return 1;
		}
	}

	/* Parse config file options */
	if(config_read(conffile) < 0) return 1;

	/* Validate config */
	if(config_validate() < 0) return 1;

	/* Check if we are doing tunnel operations only
	 * Must be done after config reading so we know tun name
	 */
	if (do_mktun || do_rmtun) {
		if (user) {
			die("Error: cannot specify -u or --user "
					"with mktun/rmtun operation");
		}
		if (group) {
			die("Error: cannot specify -g or --group "
					"with mktun/rmtun operation\n");
		}
		if (do_chroot) {
			die("Error: cannot specify -r or --chroot "
					"with mktun/rmtun operation\n");
		}
		if(tun_setup(do_mktun, do_rmtun)) exit(1);
		return 0;
	}

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
		if (write(pidfd, addrbuf, strlen(addrbuf)) != (ssize_t)strlen(addrbuf)) {
			slog(LOG_CRIT, "Error, unable to write PID file.\n");
			exit(1);
		}
		close(pidfd);
	}

	slog(LOG_INFO, "Starting tayga " TAYGA_VERSION "\n");
	slog(LOG_DEBUG, "Compiled from " TAYGA_BRANCH "\n");
	slog(LOG_DEBUG, "Commit " TAYGA_COMMIT "\n");

	if (gcfg->cache_size) {
		int urandom_fd = open("/dev/urandom", O_RDONLY);
		if (urandom_fd < 0) {
			slog(LOG_CRIT, "Unable to open /dev/urandom, "
					"aborting: %s\n", strerror(errno));
			exit(1);
		}		
		int len = 8 * sizeof(uint32_t);
		int ret = read(urandom_fd, gcfg->rand, len);
		if (ret < 0) {
			slog(LOG_CRIT, "read /dev/urandom returned %s\n",
					strerror(errno));
			exit(1);
		}
		if (ret < len) {
			slog(LOG_CRIT, "read /dev/urandom returned EOF\n");
			exit(1);
		}

		gcfg->rand[0] |= 1; /* need an odd number for IPv4 hash */
	}
	
	/* If workers is -1 (default), set to cpu cores */
	if(gcfg->workers < 0) {
		int cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
		if(cpu_cores > MAX_WORKERS) cpu_cores = MAX_WORKERS;
		if(cpu_cores < 0) {
			slog(LOG_WARNING,"Unable to detect CPU cores, defaulting to 4\n");
			cpu_cores = 4;
		}
		else {
			slog(LOG_DEBUG,"Using %d workers based on CPU core count\n",cpu_cores);
		}
		gcfg->workers = cpu_cores;
	}

	if(tun_setup(0, 0)) exit(1);

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

	/* Initialize mutexes */
	if (pthread_mutex_init(&gcfg->cache_mutex, NULL) != 0) {
		slog(LOG_CRIT, "Failed to initialize cache mutex\n");
		exit(1);
	}
	if (pthread_mutex_init(&gcfg->map_mutex, NULL) != 0) {
		slog(LOG_CRIT, "Failed to initialize map mutex\n");
		exit(1);
	}

	uint8_t * recv_buf = (uint8_t *)malloc(RECV_BUF_SIZE);
	if (!recv_buf) {
		slog(LOG_CRIT, "Error: unable to allocate %d bytes for "
				"receive buffer\n", RECV_BUF_SIZE);
		exit(1);
	}

	memset(pollfds, 0, 2 * sizeof(struct pollfd));
	pollfds[0].fd = signalfds[0];
	pollfds[0].events = POLLIN;
	pollfds[1].fd = gcfg->tun_fd;
	pollfds[1].events = POLLIN;

	/* Tell systemd logger we are ready */
	if(gcfg->log_out == LOG_TO_JOURNAL) {
		int r = notify("READY=1");
		if (r < 0) {
			slog(LOG_CRIT, "Failed to notify readiness to $NOTIFY_SOCKET: %s\n", strerror(-r));
			exit(1);
		}
	}

#ifdef __linux__
	/* Launch worker threads */
	static int thread_ids[MAX_WORKERS];
	for(int i = 0; i < gcfg->workers; i++) {
		thread_ids[i] = i;
		ret = pthread_create(&gcfg->threads[i], NULL, worker, &thread_ids[i]);
		if (ret != 0) {
			slog(LOG_CRIT, "Failed to create worker thread %d: %s\n", 
				i, strerror(ret));
			exit(1);
		}
	}
#endif

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
			tun_read(recv_buf,gcfg->tun_fd);
		if (gcfg->cache_size && (gcfg->last_cache_maint +
						CACHE_CHECK_INTERVAL < now ||
					gcfg->last_cache_maint > now)) {
			addrmap_maint();
			gcfg->last_cache_maint = now;
		}
		if (gcfg->dynamic_pool && (gcfg->last_dynamic_maint +
						POOL_CHECK_INTERVAL < now ||
					gcfg->last_dynamic_maint > now)) {
			pthread_mutex_lock(&gcfg->map_mutex);
			dynamic_maint(gcfg->dynamic_pool, 0);
			gcfg->last_dynamic_maint = now;
			pthread_mutex_unlock(&gcfg->map_mutex);
		}
	}
	return 0;
}
