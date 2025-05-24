// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800
#define ETH_P_IP6  0x86DD

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;

    /* Validate L2 header */
	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	if (ctx->protocol == bpf_htons(ETH_P_IP))
    {
        /* IPv4 packet */
        struct iphdr *l3;
        l3 = (struct iphdr *)(l2 + 1);
        if ((void *)(l3 + 1) > data_end)
            return TC_ACT_OK;          
        if(ctx->gso_segs) bpf_printk("Got IP4 packet: gso_segs %d gso_size %d", ctx->gso_segs,ctx->gso_size);
    }
    else if(ctx->protocol == bpf_htons(ETH_P_IP6))
    {
        /* IPv6 packet */
        struct ipv6hdr *l3;
        l3 = (struct ipv6hdr *)(l2 + 1);
        if ((void *)(l3 + 1) > data_end)
            return TC_ACT_OK;
            if(ctx->gso_segs) bpf_printk("Got IP6 packet: gso_segs %d gso_size %d", ctx->gso_segs,ctx->gso_size);        return TC_ACT_OK;
    }
	return TC_ACT_OK;

}

char __license[] SEC("license") = "GPL";
