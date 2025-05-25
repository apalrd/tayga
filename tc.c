// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include "tayga.h"
#include <signal.h>
#include <unistd.h>
#include "tc.skel.h"

#define LO_IFINDEX 10

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static bool hook_created = false;
static struct tc_bpf *skel;
static int err;
static struct bpf_tc_hook tc_hook;
static struct bpf_tc_opts tc_opts;
void tayga_bpf_cleanup();
void tayga_bpf_attach()
{
#ifdef CONFIG_BPF
    /* Initialize hook struct */
    memset(&tc_hook,0,sizeof(struct bpf_tc_hook));
    tc_hook.sz = sizeof(struct bpf_tc_hook);
	tc_hook.ifindex = LO_IFINDEX;
    tc_hook.attach_point = BPF_TC_INGRESS;

    /* Initialize opts struct */
    memset(&tc_opts,0,sizeof(struct bpf_tc_opts));
    tc_opts.sz = sizeof(struct bpf_tc_opts);
    tc_opts.handle = 1;
    tc_opts.priority = 1;

	libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		tayga_bpf_cleanup();
        return;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		tayga_bpf_cleanup();
        return;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
		"to see output of the BPF program.\n");
#endif
}

void tayga_bpf_detach()
{
#ifdef CONFIG_BPF
	if(hook_created) {
		tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
		err = bpf_tc_detach(&tc_hook, &tc_opts);
		if (err) {
			fprintf(stderr, "Failed to detach TC: %d\n", err);
			tayga_bpf_cleanup();
		}
	}
#endif
}

void tayga_bpf_cleanup() {
#ifdef CONFIG_BPF
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	tc_bpf__destroy(skel);
#endif
}
