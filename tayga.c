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
#include <pwd.h>
#include <grp.h>

time_t now;
static int signalfds[2];

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


static void signal_read(void)
{
	int ret, sig;

	for (;;) {
		/* Read from signalfd and check for read errors */
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
		/* If we got SIGHUP, then reload configuration */
		if(sig == SIGHUP) {
			slog(LOG_DEBUG,"Received SIGHUP, reloading\n");
			/* Reload map-file */
			addrmap_reload();
			/* Dynamic map flush to file */
			if (gcfg.dynamic_pool)
				dynamic_maint(gcfg.dynamic_pool, 1);
			continue;
		}
		/* For any other signal prepare to exit cleanly */
		if (gcfg.dynamic_pool) {
			dynamic_maint(gcfg.dynamic_pool, 1);
		}
		slog(LOG_NOTICE, "Exiting on signal %d\n", sig);
		log_cleanup();
		exit(0);
	}
}

static void print_op_info(void)
{
	struct list_head *entry;
	struct map4 *s4;
	struct map6 *s6;
	struct map6 *m6;
	struct map_static *s;
	char addrbuf[INET6_ADDRSTRLEN];
	static const char * map_types[] = MAP_TYPE_LIST;
	static const char * map_origins[] = MAP_ORIGIN_LIST;
	unsigned int type, origin;

	inet_ntop(AF_INET, &gcfg.local_addr4, addrbuf, sizeof(addrbuf));
	slog(LOG_INFO, "TAYGA's IPv4 address: %s\n", addrbuf);
	inet_ntop(AF_INET6, &gcfg.local_addr6, addrbuf, sizeof(addrbuf));
	slog(LOG_INFO, "TAYGA's IPv6 address: %s\n", addrbuf);
	m6 = list_entry(gcfg.map6_list.prev, struct map6, list);
	if (m6->type == MAP_TYPE_RFC6052) {
		inet_ntop(AF_INET6, &m6->addr, addrbuf, sizeof(addrbuf));
		slog(LOG_INFO, "NAT64 prefix: %s/%d\n",
				addrbuf, m6->prefix_len);
		if (m6->addr.s6_addr32[0] == WKPF
			&& !m6->addr.s6_addr32[1]
			&& !m6->addr.s6_addr32[2]
			&& gcfg.wkpf_strict)
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
	if (gcfg.dynamic_pool) {
		inet_ntop(AF_INET, &gcfg.dynamic_pool->map4.addr,
				addrbuf, sizeof(addrbuf));
		slog(LOG_INFO, "Dynamic pool: %s/%d\n", addrbuf,
				gcfg.dynamic_pool->map4.prefix_len);
		if (!gcfg.data_dir[0])
			slog(LOG_NOTICE, "Note: dynamically-assigned mappings "
					"will not be saved across restarts.  "
					"Specify data-dir in config if you would "
					"like dynamic mappings to be "
					"persistent.\n");
	}

	slog(LOG_DEBUG,"Map4 List:\n");
	list_for_each(entry, &gcfg.map4_list) {
		s4 = list_entry(entry, struct map4, list);
		type = (unsigned int)s4->type;
		type = (type > MAP_TYPE_MAX) ? MAP_TYPE_MAX : type;
		if(s4->type == MAP_TYPE_STATIC) {
			s = container_of(s4, struct map_static, map4);
			origin = (unsigned int)s->origin;
			origin = (origin > MAP_ORIGIN_MAX) ? MAP_ORIGIN_MAX : origin;
			slog(LOG_DEBUG,"Entry %s/%d type %s origin %s line-no %d\n",
				inet_ntop(AF_INET,&s4->addr,addrbuf,sizeof(addrbuf)),
				s4->prefix_len,
				map_types[type],
				map_origins[origin],
				s->line_no);
		} else {
			slog(LOG_DEBUG,"Entry %s/%d type %s\n",
				inet_ntop(AF_INET,&s4->addr,addrbuf,sizeof(addrbuf)),
				s4->prefix_len,map_types[type]);
		}
	}
	slog(LOG_DEBUG,"Map6 List:\n");
	list_for_each(entry, &gcfg.map6_list) {
		s6 = list_entry(entry, struct map6, list);
		type = (unsigned int)s6->type;
		type = (type > MAP_TYPE_MAX) ? MAP_TYPE_MAX : type;
		if(s6->type == MAP_TYPE_STATIC) {
			s = container_of(s6, struct map_static, map6);
			origin = (unsigned int)s->origin;
			origin = (origin > MAP_ORIGIN_MAX) ? MAP_ORIGIN_MAX : origin;
			slog(LOG_DEBUG,"Entry %s/%d type %s origin %s line-no %d\n",
				inet_ntop(AF_INET6,&s6->addr,addrbuf,sizeof(addrbuf)),
				s6->prefix_len,
				map_types[type],
				map_origins[origin],
				s->line_no);
		} else {
			slog(LOG_DEBUG,"Entry %s/%d type %s\n",
				inet_ntop(AF_INET6,&s6->addr,addrbuf,sizeof(addrbuf)),
				s6->prefix_len,map_types[type]);			
		}
	}
}

/* Worker thread for multiqueue tun interface */
#ifdef __linux__
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
		tun_read(recv_buf,gcfg.tun_fd_addl[idx]);
	}	
}
#endif //__linux__

int main(int argc, char **argv)
{
	int ret;
	int pidfd = -1;
	struct pollfd pollfds[2];
	char addrbuf[INET6_ADDRSTRLEN];
	struct passwd *pw = NULL;
	struct group *gr = NULL;

	/* Init config structure */
	config_init();

	/* Parse command line arguments */
	cmdline_parse(argc, argv);

	/* Init logging infrastructure */
	ret = log_init();
	if (ret < 0) {
		fprintf(stderr, "Error: Unable to initialize log: %s\n", strerror(-ret));
		return 1;
	}

	/* Parse config file options */
	if(config_read(arg_conffile) < 0) return 1;

	/* Validate config (and load map file) */
	if(config_validate() < 0) return 1;

	/* Check if we are doing tunnel operations only
	 * Must be done after config reading so we know tun name
	 */
	if (arg_do_mktun || arg_do_rmtun) {
		if(tun_setup(arg_do_mktun, arg_do_rmtun)) return 1;
		return 0;
	}

	/* Change user */
	if (arg_user) {
		pw = getpwnam(arg_user);
		if (!pw) {
			slog(LOG_CRIT, "Error: user %s does not exist\n", arg_user);
			return 1;
		}
	}

	/* Change group */
	if (arg_group) {
		gr = getgrnam(arg_group);
		if (!gr) {
			slog(LOG_CRIT, "Error: group %s does not exist\n",
					arg_group);
			return 1;
		}
	}

	/* Chroot */
	if (!gcfg.data_dir[0]) {
		if (arg_do_chroot) {
			slog(LOG_CRIT, "Error: cannot chroot when no data-dir "
					"is specified in %s\n", arg_conffile);
			return 1;
		}
		if (chdir("/")) {
			slog(LOG_CRIT, "Error: unable to chdir to /, aborting: %s\n",
					strerror(errno));
			return 1;
		}
	} else if (chdir(gcfg.data_dir) < 0) {
		if (arg_user || errno != ENOENT) {
			slog(LOG_CRIT, "Error: unable to chdir to %s, "
					"aborting: %s\n", gcfg.data_dir,
					strerror(errno));
			return 1;
		}
		if (mkdir(gcfg.data_dir, 0777) < 0) {
			slog(LOG_CRIT, "Error: unable to create %s, aborting: "
					"%s\n", gcfg.data_dir,
					strerror(errno));
			return 1;
		}
		if (chdir(gcfg.data_dir) < 0) {
			slog(LOG_CRIT, "Error: created %s but unable to chdir "
					"to it!?? (%s)\n", gcfg.data_dir,
					strerror(errno));
			return 1;
		}
	}

	if (arg_do_chroot && (!pw || pw->pw_uid == 0)) {
		slog(LOG_CRIT, "Error: chroot is ineffective without also "
				"specifying the -u option to switch to an "
				"unprivileged user\n");
		return 1;
	}

	/* If using a map-file, read it after doing chroot/chdir */
	if(gcfg.map_file[0] && addrmap_reload() != ERROR_NONE) {
		slog(LOG_CRIT, "Error: map-file %s is configured but not readable\n",
			gcfg.map_file);
		return 1;
	}

	if (arg_pidfile) {
		pidfd = open(arg_pidfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (pidfd < 0) {
			slog(LOG_CRIT, "Error, unable to open %s for "
					"writing: %s\n", arg_pidfile,
					strerror(errno));
			exit(1);
		}
	}

	if (arg_detach && daemon(1, 0) < 0) {
		slog(LOG_CRIT, "Error, unable to fork and detach: %s\n",
				strerror(errno));
		exit(1);
	}

	if (pidfd >= 0) {
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

	if (gcfg.cache_size) {
		int urandom_fd = open("/dev/urandom", O_RDONLY);
		if (urandom_fd < 0) {
			slog(LOG_CRIT, "Unable to open /dev/urandom, "
					"aborting: %s\n", strerror(errno));
			exit(1);
		}		
		int len = 8 * sizeof(uint32_t);
		int ret = read(urandom_fd, gcfg.rand, len);
		if (ret < 0) {
			slog(LOG_CRIT, "read /dev/urandom returned %s\n",
					strerror(errno));
			exit(1);
		}
		if (ret < len) {
			slog(LOG_CRIT, "read /dev/urandom returned EOF\n");
			exit(1);
		}

		gcfg.rand[0] |= 1; /* need an odd number for IPv4 hash */
	}
	
	/* If workers is -1 (default), set to cpu cores */
	if(gcfg.workers < 0) {
		int cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
		if(cpu_cores > MAX_WORKERS) cpu_cores = MAX_WORKERS;
		if(cpu_cores < 0) {
			slog(LOG_WARNING,"Unable to detect CPU cores, defaulting to 4\n");
			cpu_cores = 4;
		}
		else {
			slog(LOG_DEBUG,"Using %d workers based on CPU core count\n",cpu_cores);
		}
		gcfg.workers = cpu_cores;
	}

	if(tun_setup(0, 0)) exit(1);

	if (arg_do_chroot) {
		if (chroot(gcfg.data_dir) < 0) {
			slog(LOG_CRIT, "Unable to chroot to %s: %s\n",
					gcfg.data_dir, strerror(errno));
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

	/* Load dynamic maps if configured */
	if (gcfg.data_dir[0])
		load_dynamic(gcfg.dynamic_pool);

	if (gcfg.cache_size)
		create_cache();

	/* Initialize mutexes */
	if (pthread_mutex_init(&gcfg.cache_mutex, NULL) != 0) {
		slog(LOG_CRIT, "Failed to initialize cache mutex\n");
		exit(1);
	}
	if (pthread_mutex_init(&gcfg.map_mutex, NULL) != 0) {
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
	pollfds[1].fd = gcfg.tun_fd;
	pollfds[1].events = POLLIN;

	/* Tell the logger we are ready */
	ret = log_notify_ready();
	if (ret < 0) {
		slog(LOG_CRIT, "Failed to notify readiness: %s\n", strerror(-ret));
		exit(1);
	}

#ifdef __linux__
	/* Launch worker threads */
	static int thread_ids[MAX_WORKERS];
	for(int i = 0; i < gcfg.workers; i++) {
		thread_ids[i] = i;
		ret = pthread_create(&gcfg.threads[i], NULL, worker, &thread_ids[i]);
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
			signal_read();
		if (pollfds[1].revents)
			tun_read(recv_buf,gcfg.tun_fd);
		if (gcfg.cache_size && (gcfg.last_cache_maint +
						CACHE_CHECK_INTERVAL < now ||
					gcfg.last_cache_maint > now)) {
			addrmap_maint();
			gcfg.last_cache_maint = now;
		}
		if (gcfg.dynamic_pool && (gcfg.last_dynamic_maint +
						POOL_CHECK_INTERVAL < now ||
					gcfg.last_dynamic_maint > now)) {
			dynamic_maint(gcfg.dynamic_pool, 0);
			gcfg.last_dynamic_maint = now;
		}
	}
	return 0;
}
