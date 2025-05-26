/*
 *  conffile.c -- config file parser
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

struct config *gcfg;

static int parse_prefix(int af, const char *src, void *prefix, int *prefix_len)
{
	char *p, *end;
	long int a;
	int r;

	p = strchr(src, '/');
	if (!p)
		return -1;
	*p = 0;
	a = strtol(p + 1, &end, 10);
	r = *end || !inet_pton(af, src, prefix);
	*p = '/';
	if (r)
		return -1;
	if (a < 0 || a > (af == AF_INET6 ? 128 : 32))
		return -1;

	*prefix_len = a;
	return 0;
}

static struct map_static *alloc_map_static(int ln)
{
	struct map_static *m;

	m = (struct map_static *)malloc(sizeof(struct map_static));
	if (!m) {
		slog(LOG_CRIT, "Unable to allocate config memory\n");
		exit(1);
	}
	memset(m, 0, sizeof(struct map_static));
	m->map4.type = MAP_TYPE_STATIC;
	m->map4.prefix_len = 32;
	calc_ip4_mask(&m->map4.mask, NULL, 32);
	INIT_LIST_HEAD(&m->map4.list);
	m->map6.type = MAP_TYPE_STATIC;
	m->map6.prefix_len = 128;
	calc_ip6_mask(&m->map6.mask, NULL, 128);
	INIT_LIST_HEAD(&m->map6.list);
	m->conffile_lineno = ln;
	return m;
}

static void abort_on_conflict4(char *msg, int ln, struct map4 *old)
{
	char oldaddr[INET_ADDRSTRLEN];
	char oldline[128] = "";
	struct map_static *s;

	if (old->type == MAP_TYPE_STATIC || old->type == MAP_TYPE_RFC6052) {
		s = container_of(old, struct map_static, map4);
		if (s->conffile_lineno)
			sprintf(oldline, " from line %d", s->conffile_lineno);
	}

	inet_ntop(AF_INET, &old->addr, oldaddr, sizeof(oldaddr));
	if (ln)
		slog(LOG_CRIT, "%s on line %d conflicts with earlier "
				"definition of %s/%d%s\n", msg, ln,
				oldaddr, old->prefix_len, oldline);
	else
		slog(LOG_CRIT, "%s conflicts with earlier "
				"definition of %s/%d%s\n", msg,
				oldaddr, old->prefix_len, oldline);
	exit(1);
}

static void abort_on_conflict6(char *msg, int ln, struct map6 *old)
{
	char oldaddr[INET6_ADDRSTRLEN];
	char oldline[128] = "";
	struct map_static *s;

	if (old->type == MAP_TYPE_STATIC || old->type == MAP_TYPE_RFC6052) {
		s = container_of(old, struct map_static, map6);
		if (s->conffile_lineno)
			sprintf(oldline, " from line %d", s->conffile_lineno);
	}

	inet_ntop(AF_INET6, &old->addr, oldaddr, sizeof(oldaddr));
	if (ln)
		slog(LOG_CRIT, "%s on line %d overlaps with earlier "
				"definition of %s/%d%s\n", msg, ln,
				oldaddr, old->prefix_len, oldline);
	else
		slog(LOG_CRIT, "%s overlaps with earlier "
				"definition of %s/%d%s\n", msg,
				oldaddr, old->prefix_len, oldline);
	exit(1);
}

static void config_ipv4_addr(int ln, int arg_count, char **args)
{
	if (gcfg->local_addr4.s_addr) {
		slog(LOG_CRIT, "Error: duplicate ipv4-addr directive on "
				"line %d\n", ln);
		exit(1);
	}
	if (!inet_pton(AF_INET, args[0], &gcfg->local_addr4)) {
		slog(LOG_CRIT, "Expected an IPv4 address but found \"%s\" on "
				"line %d\n", args[0], ln);
		exit(1);
	}
	if (validate_ip4_addr(&gcfg->local_addr4) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in ipv4-addr "
				"directive, aborting...\n", args[0]);
		exit(1);
	}
}

static void config_ipv6_addr(int ln, int arg_count, char **args)
{
	if (gcfg->local_addr6.s6_addr[0]) {
		slog(LOG_CRIT, "Error: duplicate ipv6-addr directive on line "
				"%d\n", ln);
		exit(1);
	}
	if (!inet_pton(AF_INET6, args[0], &gcfg->local_addr6)) {
		slog(LOG_CRIT, "Expected an IPv6 address but found \"%s\" on "
				"line %d\n", args[0], ln);
		exit(1);
	}
	if (validate_ip6_addr(&gcfg->local_addr6) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in ipv6-addr "
				"directive, aborting...\n", args[0]);
		exit(1);
	}
}

static void config_prefix(int ln, int arg_count, char **args)
{
	struct map_static *m;
	struct map6 *m6;

	m = alloc_map_static(ln);
	m->map4.prefix_len = 0;
	m->map4.mask.s_addr = 0;
	m->map4.type = MAP_TYPE_RFC6052;
	m->map6.type = MAP_TYPE_RFC6052;
	m6 = &m->map6;

	if (parse_prefix(AF_INET6, args[0], &m6->addr, &m6->prefix_len) ||
			calc_ip6_mask(&m6->mask, &m6->addr, m6->prefix_len)) {
		slog(LOG_CRIT, "Expected an IPv6 prefix but found \"%s\" on "
				"line %d\n", args[0], ln);
		exit(1);
	}
	if (validate_ip6_addr(&m6->addr) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in prefix "
				"directive, aborting...\n", args[0]);
		exit(1);
	}
	if (m6->prefix_len != 32 && m6->prefix_len != 40 &&
			m6->prefix_len != 48 && m6->prefix_len != 56 &&
			m6->prefix_len != 64 && m6->prefix_len != 96) {
		slog(LOG_CRIT, "NAT prefix length must be 32, 40, 48, 56, 64 "
				"or 96 only, aborting...\n");
		exit(1);
	}
	if (insert_map4(&m->map4, NULL) < 0) {
		slog(LOG_CRIT, "Error: duplicate prefix directive on line %d\n",
				ln);
		exit(1);
	}
	if (insert_map6(&m->map6, &m6) < 0)
		abort_on_conflict6("Error: NAT64 prefix", ln, m6);
}

static void config_wkpf_strict(int ln, int arg_count, char **args)
{
	gcfg->wkpf_strict = strcmp("no",args[0]) ? 1 : 0;
}

static void config_tun_device(int ln, int arg_count, char **args)
{
	if (gcfg->tundev[0]) {
		slog(LOG_CRIT, "Error: duplicate tun-device directive on line "
				"%d\n", ln);
		exit(1);
	}
	if (strlen(args[0]) + 1 > sizeof(gcfg->tundev)) {
		slog(LOG_CRIT, "Device name \"%s\" is invalid on line %d\n",
				args[0], ln);
		exit(1);
	}
	strcpy(gcfg->tundev, args[0]);
}

static void config_map(int ln, int arg_count, char **args)
{
	struct map_static *m;
	struct map4 *m4;
	struct map6 *m6;

	m = alloc_map_static(ln);

	char *slash;
	slash = strchr(args[0], '/');
	unsigned int prefix4 = 32;
	if (slash) {
		prefix4 = atoi(slash+1);
		slash[0] = '\0';
	}

	if (!inet_pton(AF_INET, args[0], &m->map4.addr)) {
		slog(LOG_CRIT, "Expected an IPv4 subnet but found \"%s\" on "
		     "line %d\n", args[0], ln);
		exit(1);
	}
	m->map4.prefix_len = prefix4;
	calc_ip4_mask(&m->map4.mask, NULL, prefix4);

	unsigned int prefix6 = 128;
	slash = strchr(args[1], '/');
	if (slash) {
		prefix6 = atoi(slash+1);
		slash[0] = '\0';
	}

	if ((32 - prefix4) != (128 - prefix6)) {
		slog(LOG_CRIT, "IPv4 and IPv6 subnet must be of the same size, but found"
				" %s and %s on line %d\n", args[0], args[1], ln);
		exit(1);
	}

	if (!inet_pton(AF_INET6, args[1], &m->map6.addr)) {
		slog(LOG_CRIT, "Expected an IPv6 subnet but found \"%s\" on "
				"line %d\n", args[1], ln);
		exit(1);
	}
	m->map6.prefix_len = prefix6;
	calc_ip6_mask(&m->map6.mask, NULL, prefix6);
        
	if (validate_ip4_addr(&m->map4.addr) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in map "
				"directive, aborting...\n", args[0]);
		exit(1);
	}
	if (validate_ip6_addr(&m->map6.addr) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in map "
				"directive, aborting...\n", args[1]);
		exit(1);
	}
	if (m->map6.addr.s6_addr32[0] == WKPF &&
	    m->map6.addr.s6_addr32[1] == 0 &&
	    m->map6.addr.s6_addr32[2] == 0) {
		if(gcfg->wkpf_strict)
		{
			slog(LOG_CRIT, "Cannot create single-host maps inside "
					"64:ff9b::/96, aborting...\n");
			exit(1);
		}
		else 
		{
			slog(LOG_INFO, "Should not create single-host maps inside "
					"64:ff9b::/96, however strict RFC60252"
					" compliance is disabled\n");
		}
	}
	if (insert_map4(&m->map4, &m4) < 0)
		abort_on_conflict4("Error: IPv4 address in map directive",
				ln, m4);
	if (insert_map6(&m->map6, &m6) < 0)
		abort_on_conflict6("Error: IPv6 address in map directive",
				ln, m6);
}

static void config_dynamic_pool(int ln, int arg_count, char **args)
{
	struct dynamic_pool *pool;
	struct map4 *m4;

	if (gcfg->dynamic_pool) {
		slog(LOG_CRIT, "Error: duplicate dynamic-pool directive on "
				"line %d\n", ln);
		exit(1);
	}

	pool = (struct dynamic_pool *)malloc(sizeof(struct dynamic_pool));
	if (!pool) {
		slog(LOG_CRIT, "Unable to allocate config memory\n");
		exit(1);
	}
	memset(pool, 0, sizeof(struct dynamic_pool));
	INIT_LIST_HEAD(&pool->mapped_list);
	INIT_LIST_HEAD(&pool->dormant_list);
	INIT_LIST_HEAD(&pool->free_list);

	m4 = &pool->map4;
	m4->type = MAP_TYPE_DYNAMIC_POOL;
	INIT_LIST_HEAD(&m4->list);

	if (parse_prefix(AF_INET, args[0], &m4->addr, &m4->prefix_len) ||
			calc_ip4_mask(&m4->mask, &m4->addr, m4->prefix_len)) {
		slog(LOG_CRIT, "Expected an IPv4 prefix but found \"%s\" on "
				"line %d\n", args[0], ln);
		exit(1);
	}
	if (validate_ip4_addr(&m4->addr) < 0) {
		slog(LOG_CRIT, "Cannot use reserved address %s in dynamic-pool "
				"directive, aborting...\n", args[0]);
		exit(1);
	}
	if (m4->prefix_len > 31) {
		slog(LOG_CRIT, "Cannot use a prefix longer than /31 in "
			       "dynamic-pool directive, aborting...\n");
		exit(1);
	}
	if (insert_map4(&pool->map4, &m4) < 0)
		abort_on_conflict4("Error: IPv4 prefix in dynamic-pool "
				"directive", ln, m4);

	pool->free_head.addr = ntohl(m4->addr.s_addr);
	pool->free_head.count = (1 << (32 - m4->prefix_len)) - 1;
	INIT_LIST_HEAD(&pool->free_head.list);
	list_add(&pool->free_head.list, &pool->free_list);

	gcfg->dynamic_pool = pool;
}

static void config_data_dir(int ln, int arg_count, char **args)
{
	if (gcfg->data_dir[0]) {
		slog(LOG_CRIT, "Error: duplicate data-dir directive on line "
				"%d\n", ln);
		exit(1);
	}
	if (args[0][0] != '/') {
		slog(LOG_CRIT, "Error: data-dir must be an absolute path\n");
		exit(1);
	}
	strcpy(gcfg->data_dir, args[0]);
}

static void config_strict_fh(int ln, int arg_count, char **args)
{
	if (!strcasecmp(args[0], "true") || !strcasecmp(args[0], "on") ||
			!strcasecmp(args[0], "1")) {
		gcfg->lazy_frag_hdr = 0;
	} else if (!strcasecmp(args[0], "false") ||
			!strcasecmp(args[0], "off") ||
			!strcasecmp(args[0], "0")) {
		gcfg->lazy_frag_hdr = 1;
	} else {
		slog(LOG_CRIT, "Error: invalid value for strict-frag-hdr\n");
		exit(1);
	}
}

struct {
	char *name;
	void (*config_func)(int ln, int arg_count, char **args);
	int need_args;
} config_directives[] = {
	{ "ipv4-addr", config_ipv4_addr, 1 },
	{ "ipv6-addr", config_ipv6_addr, 1 },
	{ "prefix", config_prefix, 1 },
	{ "wkpf-strict", config_wkpf_strict, 1 },
	{ "tun-device", config_tun_device, 1 },
	{ "map", config_map, 2 },
	{ "dynamic-pool", config_dynamic_pool, 1 },
	{ "data-dir", config_data_dir, 1 },
	{ "strict-frag-hdr", config_strict_fh, 1 },
	{ NULL, NULL, 0 }
};

void read_config(char *conffile)
{
	FILE *in;
	int ln = 0;
	char line[512];
	char addrbuf[128];
	char *c, *tokptr;
#define MAX_ARGS 10
	char *args[MAX_ARGS];
	int arg_count;
	int i;
	struct map_static *m;
	struct map4 *m4;
	struct map6 *m6;

	gcfg = (struct config *)malloc(sizeof(struct config));
	if (!gcfg)
		goto malloc_fail;
	memset(gcfg, 0, sizeof(struct config));
	gcfg->recv_buf_size = 65536 + sizeof(struct tun_pi);
	INIT_LIST_HEAD(&gcfg->map4_list);
	INIT_LIST_HEAD(&gcfg->map6_list);
	gcfg->dyn_min_lease = 7200 + 4 * 60; /* just over two hours */
	gcfg->dyn_max_lease = 14 * 86400;
	gcfg->max_commit_delay = gcfg->dyn_max_lease / 4;
	gcfg->hash_bits = 7;
	gcfg->cache_size = 8192;
	gcfg->ipv6_offlink_mtu = 1280;
	gcfg->lazy_frag_hdr = 1;
	INIT_LIST_HEAD(&gcfg->cache_pool);
	INIT_LIST_HEAD(&gcfg->cache_active);
	gcfg->wkpf_strict = 1;

	in = fopen(conffile, "r");
	if (!in) {
		slog(LOG_CRIT, "unable to open %s, aborting: %s\n", conffile,
				strerror(errno));
		exit(1);
	}
	while (fgets(line, sizeof(line), in)) {
		++ln;
		if (strlen(line) + 1 == sizeof(line)) {
			slog(LOG_CRIT, "Line %d of %s is too long, "
					"aborting...\n", ln, conffile);
			exit(1);
		}
		arg_count = 0;
		for (;;) {
			c = strtok_r(arg_count ? NULL : line, DELIM, &tokptr);
			if (!c || *c == '#')
				break;
			if (arg_count == MAX_ARGS) {
				slog(LOG_CRIT, "Line %d of %s is too long, "
						"aborting...\n", ln, conffile);
				exit(1);
			}
			args[arg_count++] = c;
		}
		if (arg_count == 0)
			continue;
		for (i = 0; config_directives[i].name; ++i)
			if (!strcasecmp(args[0], config_directives[i].name))
				break;
		if (!config_directives[i].name) {
			slog(LOG_CRIT, "Unknown directive \"%s\" on line %d of "
					"%s, aborting...\n", args[0],
					ln, conffile);
			exit(1);
		}
		--arg_count;
		if (config_directives[i].need_args >= 0 &&
				arg_count != config_directives[i].need_args) {
			slog(LOG_CRIT, "Incorrect number of arguments on "
					"line %d\n", ln);
			exit(1);
		}
		config_directives[i].config_func(ln, arg_count, &args[1]);
	}
	fclose(in);

	if (list_empty(&gcfg->map6_list)) {
		slog(LOG_CRIT, "Error: no translation maps or NAT64 prefix "
				"configured\n");
		exit(1);
	}

	m4 = list_entry(gcfg->map4_list.next, struct map4, list);
	m6 = list_entry(gcfg->map6_list.next, struct map6, list);

	if (m4->type == MAP_TYPE_RFC6052 && m6->type == MAP_TYPE_RFC6052) {
		slog(LOG_DEBUG,"Disabling cache, not required\n");
		gcfg->cache_size = 0;
	}
	
	if (!gcfg->local_addr4.s_addr) {
		slog(LOG_CRIT, "Error: no ipv4-addr directive found\n");
		exit(1);
	}

	m = alloc_map_static(0);
	m->map4.addr = gcfg->local_addr4;
	if (insert_map4(&m->map4, &m4) < 0)
		abort_on_conflict4("Error: ipv4-addr", 0, m4);

	if (gcfg->local_addr6.s6_addr32[0]) {
		m->map6.addr = gcfg->local_addr6;
		if (insert_map6(&m->map6, &m6) < 0) {
			if (m6->type == MAP_TYPE_RFC6052) {
				inet_ntop(AF_INET6, &m6->addr,
						addrbuf, sizeof(addrbuf));
				slog(LOG_CRIT, "Error: ipv6-addr cannot reside "
						"within configured prefix "
						"%s/%d\n", addrbuf,
						m6->prefix_len);
				exit(1);
			} else {
				abort_on_conflict6("Error: ipv6-addr", 0, m6);
			}
		}
	} else {
		m6 = list_entry(gcfg->map6_list.prev, struct map6, list);
		if (m6->type != MAP_TYPE_RFC6052) {
			slog(LOG_CRIT, "Error: ipv6-addr directive must be "
					"specified if no NAT64 prefix is "
					"configured\n");
			exit(1);
		}
		if (append_to_prefix(&gcfg->local_addr6, &gcfg->local_addr4,
					&m6->addr, m6->prefix_len)) {
			if(gcfg->wkpf_strict)
			{
				slog(LOG_CRIT, "Error: ipv6-addr directive must be "
						"specified if prefix is 64:ff9b::/96 "
						"and ipv4-addr is a non-global "
						"(RFC 1918) address\n");
				exit(1);
			}
		}
		m->map6.addr = gcfg->local_addr6;
	}
	
	if (gcfg->local_addr6.s6_addr32[0] == WKPF &&
		gcfg->local_addr6.s6_addr32[1] == 0 &&
		gcfg->local_addr6.s6_addr32[2] == 0 &&
		gcfg->wkpf_strict)
	{
		slog(LOG_CRIT, "Error: ipv6-addr directive cannot contain an "
				"address in the Well-Known Prefix "
				"(64:ff9b::/96)\n");
		exit(1);
	}
	return;

malloc_fail:
	slog(LOG_CRIT, "Unable to allocate config memory\n");
	exit(1);
}

/*
Local Variables:
c-basic-offset: 8
indent-tabs-mode: t
End:
*/
