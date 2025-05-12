/*
 *  dynamic.c -- dynamic address mapper
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

#define MAP_FILE	"dynamic.map"
#define TMP_MAP_FILE	"dynamic.map~~"

extern struct config *gcfg;
extern time_t now;

static struct map_dynamic *alloc_map_dynamic(const struct in6_addr *addr6,
		const struct in_addr *addr4, struct free_addr *f)
{
	struct map_dynamic *d;
	uint32_t a = ntohl(addr4->s_addr);

	d = (struct map_dynamic *)malloc(sizeof(struct map_dynamic));
	if (!d) {
		slog(LOG_CRIT, "Unable to allocate memory\n");
		return NULL;
	}
	memset(d, 0, sizeof(struct map_dynamic));
	INIT_LIST_HEAD(&d->list);

	d->map4.type = MAP_TYPE_DYNAMIC_HOST;
	d->map4.addr = *addr4;
	d->map4.prefix_len = 32;
	calc_ip4_mask(&d->map4.mask, NULL, 32);
	INIT_LIST_HEAD(&d->map4.list);

	d->map6.type = MAP_TYPE_DYNAMIC_HOST;
	d->map6.addr = *addr6;
	d->map6.prefix_len = 128;
	calc_ip6_mask(&d->map6.mask, NULL, 128);
	INIT_LIST_HEAD(&d->map6.list);

	d->free.addr = a;
	d->free.count = f->count - (a - f->addr);
	f->count = a - f->addr - 1;
	INIT_LIST_HEAD(&d->free.list);
	list_add(&d->free.list, &f->list);

	return d;
}

static void move_to_mapped(struct map_dynamic *d, struct dynamic_pool *pool)
{
	insert_map4(&d->map4, NULL);
	insert_map6(&d->map6, NULL);
	list_add(&d->list, &pool->mapped_list);
}

static void move_to_dormant(struct map_dynamic *d, struct dynamic_pool *pool)
{
	struct list_head *entry;
	struct map_dynamic *s;

	list_del(&d->map4.list);
	list_del(&d->map6.list);

	if (list_empty(&pool->dormant_list)) {
		list_add_tail(&d->list, &pool->dormant_list);
		return;
	}

	s = list_entry(pool->dormant_list.prev, struct map_dynamic, list);
	if (s->last_use >= d->last_use) {
		list_add_tail(&d->list, &pool->dormant_list);
		return;
	}

	list_for_each(entry, &pool->dormant_list) {
		s = list_entry(entry, struct map_dynamic, list);
		if (s->last_use < d->last_use)
			break;
	}
	list_add_tail(&d->list, entry);
}

static void print_dyn_change(char *str, struct map_dynamic *d)
{
	char addrbuf4[INET_ADDRSTRLEN];
	char addrbuf6[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET, &d->map4.addr, addrbuf4, sizeof(addrbuf4));
	inet_ntop(AF_INET6, &d->map6.addr, addrbuf6, sizeof(addrbuf6));
	slog(LOG_DEBUG, "%s pool address %s (%s)\n", str, addrbuf4, addrbuf6);
}

struct map6 *assign_dynamic(const struct in6_addr *addr6)
{
	struct dynamic_pool *pool;
	struct list_head *entry;
	struct free_addr *f;
	uint32_t i, addr, base, max;
	struct in_addr addr4;
	struct map4 *m4;
	struct map_dynamic *d;

	pool = gcfg->dynamic_pool;
	if (!pool)
		return NULL;

	list_for_each(entry, &pool->dormant_list) {
		d = list_entry(entry, struct map_dynamic, list);
		if (IN6_ARE_ADDR_EQUAL(addr6, &d->map6.addr)) {
			print_dyn_change("reactivated dormant", d);
			goto activate;
		}
	}

	base = 0;
	max = (1 << (32 - pool->map4.prefix_len)) - 1;

	for (i = 0; i < 4; ++i) {
		base += addr6->s6_addr32[i];
		while (base & ~max)
			base = (base & max) +
				(base >> (32 - pool->map4.prefix_len));
	}

	for (i = 0, entry = NULL; i <= max; ++i) {
		addr = pool->free_head.addr | ((base + i) & max);
		if (!entry || addr == pool->free_head.addr)
			entry = pool->free_list.next;
		for (;;) {
			f = list_entry(entry, struct free_addr, list);
			if (f->addr + f->count >= addr)
				break;
			entry = entry->next;
		}
		if (f->addr >= addr)
			continue;
		addr4.s_addr = htonl(addr);
		m4 = find_map4(&addr4);
		if (m4 == &pool->map4) {
			d = alloc_map_dynamic(addr6, &addr4, f);
			if (!d)
				return NULL;
			print_dyn_change("assigned new", d);
			gcfg->map_write_pending = 1;
			goto activate;
		}
	}

	if (list_empty(&pool->dormant_list))
		return NULL;

	d = list_entry(pool->dormant_list.prev, struct map_dynamic, list);
	d->map6.addr = *addr6;
	print_dyn_change("reassigned dormant", d);
	gcfg->map_write_pending = 1;

activate:
	move_to_mapped(d, pool);
	return &d->map6;
}

static void load_map(struct dynamic_pool *pool, const struct in6_addr *addr6,
		const struct in_addr *addr4, long int last_use)
{
	struct list_head *entry;
	struct free_addr *f;
	uint32_t addr;
	struct map4 *m4;
	struct map_dynamic *d;
	char addrbuf4[INET_ADDRSTRLEN];
	char addrbuf6[INET6_ADDRSTRLEN];

	if (pool->map4.addr.s_addr != (addr4->s_addr &
					pool->map4.mask.s_addr)) {
		inet_ntop(AF_INET, addr4, addrbuf4, sizeof(addrbuf4));
		slog(LOG_NOTICE, "Ignoring map for %s from %s/%s that lies "
				"outside dynamic pool prefix\n", addrbuf4,
				gcfg->data_dir, MAP_FILE);
		return;
	}
	m4 = find_map4(addr4);
	if (m4 != &pool->map4) {
		inet_ntop(AF_INET, addr4, addrbuf4, sizeof(addrbuf4));
		slog(LOG_NOTICE, "Ignoring map for %s from %s/%s that "
				"conflicts with statically-configured map\n",
				addrbuf4, gcfg->data_dir, MAP_FILE);
		return;
	}
	if (validate_ip6_addr(addr6) < 0) {
		inet_ntop(AF_INET, addr4, addrbuf4, sizeof(addrbuf4));
		inet_ntop(AF_INET6, addr6, addrbuf6, sizeof(addrbuf6));
		slog(LOG_NOTICE, "Ignoring map for %s from %s/%s with "
				"invalid IPv6 address %s\n", addrbuf4,
				gcfg->data_dir, MAP_FILE, addrbuf6);
		return;
	}
	if (find_map6(addr6)) {
		inet_ntop(AF_INET6, addr6, addrbuf6, sizeof(addrbuf6));
		slog(LOG_NOTICE, "Ignoring map for %s from %s/%s that "
				"conflicts with statically-configured map\n",
				addrbuf6, gcfg->data_dir, MAP_FILE);
		return;
	}
	addr = ntohl(addr4->s_addr);
	list_for_each(entry, &pool->free_list) {
		f = list_entry(entry, struct free_addr, list);
		if (f->addr + f->count >= addr)
			break;
	}
	if (entry == &pool->free_list || f->addr >= addr) {
		inet_ntop(AF_INET, addr4, addrbuf4, sizeof(addrbuf4));
		slog(LOG_NOTICE, "Ignoring duplicate map for %s from %s/%s\n",
				addrbuf4, gcfg->data_dir, MAP_FILE);
		return;
	}
	d = alloc_map_dynamic(addr6, addr4, f);
	if (!d)
		return;
	d->last_use = last_use;
	move_to_dormant(d, pool);
}

void load_dynamic(struct dynamic_pool *pool)
{
	FILE *in;
	char line[512];
	char *s4, *s6, *stime, *end, *tokptr;
	struct in_addr addr4;
	struct in6_addr addr6;
	long int last_use;
	struct list_head *entry;
	struct map_dynamic *d;
	int count = 0;

	in = fopen(MAP_FILE, "r");
	if (!in) {
		if (errno != ENOENT)
			slog(LOG_ERR, "Unable to open %s/%s, ignoring: %s\n",
					gcfg->data_dir, MAP_FILE,
					strerror(errno));
		return;
	}
	while (fgets(line, sizeof(line), in)) {
		if (strlen(line) + 1 == sizeof(line)) {
			slog(LOG_ERR, "Ignoring oversized line in %s/%s\n",
					gcfg->data_dir, MAP_FILE);
			continue;
		}
		s4 = strtok_r(line, DELIM, &tokptr);
		if (!s4 || *s4 == '#')
			continue;
		s6 = strtok_r(NULL, DELIM, &tokptr);
		if (!s6)
			goto malformed;
		stime = strtok_r(NULL, DELIM, &tokptr);
		if (!stime)
			goto malformed;
		end = strtok_r(NULL, DELIM, &tokptr);
		if (end)
			goto malformed;
		if (!inet_pton(AF_INET, s4, &addr4) ||
				!inet_pton(AF_INET6, s6, &addr6))
			goto malformed;
		last_use = strtol(stime, &end, 10);
		if (last_use <= 0 || *end)
			goto malformed;
		load_map(pool, &addr6, &addr4, last_use);
		continue;
malformed:
		slog(LOG_ERR, "Ignoring malformed line in %s/%s\n",
				gcfg->data_dir, MAP_FILE);
	}
	fclose(in);

	time(&now);
	last_use = 0;
	list_for_each(entry, &pool->dormant_list) {
		d = list_entry(entry, struct map_dynamic, list);
		if (d->last_use > last_use)
			last_use = d->last_use;
		++count;
	}
	slog(LOG_INFO, "Loaded %d dynamic %s from %s/%s\n", count,
			count == 1 ? "map" : "maps",
			gcfg->data_dir, MAP_FILE);
	if (last_use > now) {
		slog(LOG_DEBUG, "Note: maps in %s/%s are dated in the future\n",
				gcfg->data_dir, MAP_FILE);
		list_for_each(entry, &pool->dormant_list) {
			d = list_entry(entry, struct map_dynamic, list);
			d->last_use = now - gcfg->dyn_min_lease;
		}
	} else {
		while (!list_empty(&pool->dormant_list)) {
			d = list_entry(pool->dormant_list.next,
					struct map_dynamic, list);
			if (d->last_use + gcfg->dyn_min_lease < now)
				break;
			move_to_mapped(d, pool);
		}
	}
}

static void write_to_file(struct dynamic_pool *pool)
{
	FILE *out;
	struct list_head *entry;
	struct map_dynamic *d;
	char addrbuf4[INET_ADDRSTRLEN];
	char addrbuf6[INET6_ADDRSTRLEN];

	out = fopen(TMP_MAP_FILE, "w");
	if (!out) {
		slog(LOG_ERR, "Unable to open %s/%s for writing: %s\n",
				gcfg->data_dir, TMP_MAP_FILE,
				strerror(errno));
		return;
	}
	fprintf(out, "###\n###\n### TAYGA dynamic map database\n###\n"
			"### You can edit this (carefully!) as long as "
			"you shut down TAYGA first\n###\n###\n"
			"### Last written: %s###\n###\n\n",
			asctime(gmtime(&now)));
	entry = pool->mapped_list.next;
	while (entry != &pool->dormant_list) {
		if (entry == &pool->mapped_list) {
			entry = pool->dormant_list.next;
			continue;
		}
		d = list_entry(entry, struct map_dynamic, list);
		inet_ntop(AF_INET, &d->map4.addr, addrbuf4, sizeof(addrbuf4));
		inet_ntop(AF_INET6, &d->map6.addr, addrbuf6, sizeof(addrbuf6));
		fprintf(out, "%s\t%s\t%ld\n", addrbuf4, addrbuf6,
				d->cache_entry ?
					d->cache_entry->last_use : d->last_use);
		entry = entry->next;
	}
	fclose(out);
	if (rename(TMP_MAP_FILE, MAP_FILE) < 0) {
		slog(LOG_ERR, "Unable to rename %s/%s to %s/%s: %s\n",
				gcfg->data_dir, TMP_MAP_FILE,
				gcfg->data_dir, MAP_FILE,
				strerror(errno));
		unlink(TMP_MAP_FILE);
	}
}

void dynamic_maint(struct dynamic_pool *pool, int shutdown)
{
	struct list_head *entry, *next;
	struct map_dynamic *d;
	struct free_addr *f;

	list_for_each_safe(entry, next, &pool->mapped_list) {
		d = list_entry(entry, struct map_dynamic, list);
		if (d->cache_entry)
			continue;
		if (d->last_use + gcfg->dyn_min_lease < now) {
			print_dyn_change("unmapped dormant", d);
			move_to_dormant(d, pool);
		}
	}
	while (!list_empty(&pool->dormant_list)) {
		d = list_entry(pool->dormant_list.prev,
				struct map_dynamic, list);
		if (d->last_use + gcfg->dyn_max_lease >= now)
			break;
		f = list_entry(d->free.list.prev, struct free_addr, list);
		f->count += d->free.count + 1;
		list_del(&d->free.list);
		list_del(&d->list);
		free(d);
	}
	if (gcfg->data_dir[0]) {
		if (shutdown || gcfg->map_write_pending ||
				gcfg->last_map_write +
					gcfg->max_commit_delay < now ||
				gcfg->last_map_write > now) {
			write_to_file(pool);
			gcfg->last_map_write = now;
			gcfg->map_write_pending = 0;
		}
	}
}
