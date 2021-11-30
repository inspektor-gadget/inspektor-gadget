// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

/* This BPF program uses the GPL-restricted function bpf_probe_read*().
 */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "tracepkt.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// bpf/bpf_tracing.h only defines PT_REGS_PARMx up to 5.
#ifndef PT_REGS_PARM6
  #if defined(bpf_target_x86)
    #define PT_REGS_PARM6(x) ((x)->r9)
  #elif defined(bpf_target_arm64)
    #define PT_REGS_PARM5(x) (((PT_REGS_ARM64 *)(x))->regs[5])
  #else
    #error "Please define PT_REGS_PARM6 for your architecture"
  #endif
#endif

SEC("kprobe/nf_log_trace")
int kprobe_nf_log_trace(struct pt_regs *ctx)
	// arg1
	// struct net *net,
	// arg2
	// u_int8_t pf,
	// arg3
	// unsigned int hooknum,
	// arg4
	// struct sk_buff *skb,
	// arg5
	// struct net_device *in,
	// arg6
	// struct net_device *out)
	// arg7: *(esp+8) 
	//struct nf_loginfo *loginfo,
	// arg8: *(esp+16) 
	//const char *fmt,
	// arg8: *(esp+24) 
	//char *tablename,
	// arg8: *(esp+32) 
	//char *chainname, // "PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"
	// arg8: *(esp+40) 
	//char *comment, // "rule", "return", "policy"
	// arg9: *(esp+48) 
	//unsigned int rulenum)
{
	struct net *net = (struct net *)PT_REGS_PARM1(ctx);
	u_int8_t pf = PT_REGS_PARM2(ctx);
	unsigned int hooknum = PT_REGS_PARM3(ctx);
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
	struct net_device *in = (struct net_device *)PT_REGS_PARM5(ctx);
	struct net_device *out = (struct net_device *)PT_REGS_PARM6(ctx);
	char **tablename_ptr = (char **)((char *)(PT_REGS_SP(ctx)) + 24);
	char *tablename;
	char **chainname_ptr = (char **)((char *)(PT_REGS_SP(ctx)) + 32);
	char *chainname;
	char **comment_ptr = (char **)((char *)(PT_REGS_SP(ctx)) + 40);
	char *comment;
	unsigned int *rulenum_ptr = (unsigned int*)((char *)PT_REGS_SP(ctx) + 48);
	unsigned int rulenum;

	struct event_t event = {0,};

	if (in != 0) {
		event.netns_in = BPF_CORE_READ(in, nd_net.net, ns.inum);
		event.ifindex_in = BPF_CORE_READ(in, ifindex);
		bpf_probe_read_kernel(&event.ifname_in, IFNAMSIZ, in->name);
	}

	if (out != 0) {
		event.netns_out = BPF_CORE_READ(out, nd_net.net, ns.inum);
		event.ifindex_out = BPF_CORE_READ(out, ifindex);
		bpf_probe_read_kernel(&event.ifname_out, IFNAMSIZ, out->name);
	}

	bpf_probe_read_kernel(&tablename, sizeof(void*), tablename_ptr);
	bpf_probe_read_kernel_str(&event.tablename, TABLENAMESIZ, tablename);

	bpf_probe_read_kernel(&chainname, sizeof(void*), chainname_ptr);
	bpf_probe_read_kernel_str(&event.chainname, CHAINNAMESIZ, chainname);

	bpf_probe_read_kernel(&comment, sizeof(void*), comment_ptr);
	bpf_probe_read_kernel_str(&event.comment, COMMENTSIZ, comment);

	bpf_probe_read_kernel(&event.rulenum, sizeof(long long unsigned int), rulenum_ptr);

	bpf_printk("nf_log_trace: pf '%u'", pf);
	bpf_printk("nf_log_trace: hooknum '%u'", hooknum);
	bpf_printk("nf_log_trace: ifaces in='%s' out='%s'", event.ifname_in, event.ifname_out);
	bpf_printk("nf_log_trace: ifaces in='%d' out='%d'", event.ifindex_in, event.ifindex_out);
	bpf_printk("nf_log_trace: tablename '%s'", event.tablename);
	bpf_printk("nf_log_trace: chainname '%s'", event.chainname);
	bpf_printk("nf_log_trace: comment '%s'", event.comment);
	bpf_printk("nf_log_trace: rulenum '%u'", event.rulenum);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
