// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation

#include <vmlinux.h>

/* I am directly including the 
value of the constants instead of 
the linux/if_ether.h header file and linux/pkt_cls.h
because of redeclaration conflicts with
vmlinux.h */

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7

#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define TASK_COMM_LEN 16

struct events_map_key {
	struct gadget_l4endpoint_t dst;
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
	__u64 delay_ns;

	gadget_netns_id netns_id;
	struct gadget_process proc;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key,
	       struct events_map_key); // The key is going to be L4 gadget endpoint
	__type(value, struct event);
} events_map SEC(".maps");

GADGET_MAPITER(events_map_iter, events_map);

const volatile __u64 delay_ns = 500000000; // 500ms in nanoseconds

GADGET_PARAM(delay_ns);

SEC("classifier/egress/drop")
int delay_dns_packets(struct __sk_buff *skb) {
    struct events_map_key
		key; /* This is the key for events_map -> being the target addr,port pair */
	struct sockets_key
		sockets_key_for_md; /* This is for socket enrichement map */
	struct event
		event; /* The struct to store the information regarding the event */ 

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip4h;
	struct ipv6hdr *ip6h;

    /* Check if the ethernet headers are invalid if so ignore 
	   the packets, else do the further processing	 */
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_OK; // Eth headers incomplete - Letting them pass through the without further processing
	}

    switch (bpf_ntohs(eth->h_proto)) {
	default:
		return TC_ACT_OK; // Unhandled protocol, pass through
	case ETH_P_IP: // IPv4 Processing    
            ip4h = (struct iphdr *)(eth + 1);

            /* Check if IPv4 headers are invalid */
            if ((void *)(ip4h + 1) > data_end)
                return TC_ACT_OK;

            if(ip4h->protocol == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));

                if ((void *)(udph + 1) > data_end) {
                    return TC_ACT_OK;
                }

                if (bpf_ntohs(udph->dest) == 53 || bpf_ntohs(udph->source) == 53) {
                    __u64 current_time = bpf_ktime_get_ns();

                    // Add delay to skb tstamp
                    skb->tstamp = current_time + delay_ns;

                    key.dst.addr_raw.v4 = ip4h->daddr;
                    event.src.version = key.dst.version = 4;
                    key.dst.port = skb->pkt_type == SE_PACKET_HOST ?
                                            bpf_ntohs(udph->dest) :
                                            bpf_ntohs(udph->source);
                    event.src.proto_raw = key.dst.proto_raw = sockets_key_for_md.proto = IPPROTO_UDP;
                    event.delay_ns = delay_ns;
                    event.src.addr_raw.v4 = ip4h->saddr;
                    sockets_key_for_md.family = SE_AF_INET;
                    event.netns_id = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c to get the netns
                    sockets_key_for_md.netns = event.netns_id;
                    event.proc.comm[0] = '\0';
                    event.proc.parent.comm[0] = '\0';
                    

                    struct sockets_value *skb_val = bpf_map_lookup_elem(
                    &gadget_sockets, &sockets_key_for_md);
                    if (skb_val != NULL) {
                        event.proc.mntns_id = skb_val->mntns;
                        event.proc.pid = skb_val->pid_tgid >> 32;
                        event.proc.tid = (__u32)skb_val->pid_tgid;
                        event.proc.parent.pid = skb_val->ppid;
                        __builtin_memcpy(&event.proc.comm,
                                skb_val->task,
                                sizeof(event.proc.comm));
                        __builtin_memcpy(
                            &event.proc.parent.comm,
                            skb_val->ptask,
                            sizeof(event.proc.parent.comm));
                        event.proc.creds.uid = (__u32)skb_val->uid_gid;
                        event.proc.creds.gid =
                            (__u32)(skb_val->uid_gid >> 32);
                    }
                    event.timestamp_raw = bpf_ktime_get_boot_ns();
                    bpf_map_update_elem(&events_map, &key, &event,
                                BPF_NOEXIST);

                    return TC_ACT_OK;
                }
            }
            break;
    case ETH_P_IPV6: // IPv6 Processing
            ip6h = (struct ipv6hdr *)(eth + 1);
            /* Check if IPv6 headers are invalid */
            if ((void *)(ip6h + 1) > data_end)
                return TC_ACT_OK;

            if(ip6h->nexthdr == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)(ip6h + 1);
                if ((void *)(udph + 1) > data_end) return TC_ACT_OK;

                if (bpf_ntohs(udph->dest) == 53 || bpf_ntohs(udph->source) == 53) {
                    __u64 current_time = bpf_ktime_get_ns();

                    // Add delay to skb tstamp
                    skb->tstamp = current_time + delay_ns;

                    __builtin_memcpy(&key.dst.addr_raw.v6, &ip6h->daddr, sizeof(key.dst.addr_raw.v6));
                    event.src.version = key.dst.version = 6;
                    key.dst.port = skb->pkt_type == SE_PACKET_HOST ?
                                            bpf_ntohs(udph->dest) :
                                            bpf_ntohs(udph->source);
                    event.src.proto_raw = key.dst.proto_raw = sockets_key_for_md.proto = IPPROTO_UDP;
                    event.delay_ns = delay_ns;
                    __builtin_memcpy(&event.src.addr_raw.v6, &ip6h->saddr, sizeof(event.src.addr_raw.v6));
                    sockets_key_for_md.family = SE_AF_INET6;
                    event.netns_id = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c to get the netns
                    sockets_key_for_md.netns = event.netns_id;
                    event.proc.comm[0] = '\0';
                    event.proc.parent.comm[0] = '\0';
                    

                    struct sockets_value *skb_val = bpf_map_lookup_elem(
                        &gadget_sockets, &sockets_key_for_md);
                    if (skb_val != NULL) {  
                        event.proc.mntns_id = skb_val->mntns;
                        event.proc.pid = skb_val->pid_tgid >> 32;
                        event.proc.tid = (__u32)skb_val->pid_tgid;
                        event.proc.parent.pid = skb_val->ppid;
                        __builtin_memcpy(&event.proc.comm,
                                skb_val->task,
                                sizeof(event.proc.comm));
                        __builtin_memcpy(
                            &event.proc.parent.comm,
                            skb_val->ptask,
                            sizeof(event.proc.parent.comm));
                        event.proc.creds.uid = (__u32)skb_val->uid_gid;
                        event.proc.creds.gid =
                            (__u32)(skb_val->uid_gid >> 32);
                    }
                    event.timestamp_raw = bpf_ktime_get_boot_ns();
                    bpf_map_update_elem(&events_map, &key, &event,
                                BPF_NOEXIST);

                    return TC_ACT_OK;
                }
            }
            break;
        }

    return TC_ACT_OK; // Pass through non-DNS packets
}

char _license[] SEC("license") = "GPL";
