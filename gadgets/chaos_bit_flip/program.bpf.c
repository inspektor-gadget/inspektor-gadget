// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation


#include <vmlinux.h>

/* I am directly including the 
value of the constants instead of 
the linux/if_ether.h header file and linux/pkt_cls.h
because of redeclration conflicts with
vmlinux.h */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/


#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7

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

typedef struct {
    __u64 a;
    __u64 b;
} __u128;

struct events_map_key{
	struct gadget_l4endpoint_t dst;
	/* another field to indicate source or destination */
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
    gadget_counter__u32 flip_cnt;
	bool ingress;
	bool egress;

	gadget_mntns_id mntns_id;
	gadget_netns_id netns_id;

	char comm[TASK_COMM_LEN];
	char pcomm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key,struct events_map_key);	// The key is going to be <dst addr,port> pair
	__type(value,struct event);
} events_map SEC(".maps");

GADGET_MAPITER(events_map_iter,events_map);

// we use the following variables as parameters
volatile const __u32 ipaddr_v4_filter = 0;
volatile const __u128 ipaddr_v6_filter =  {0,0}; 
const volatile __u16 port = 0;
const volatile __u32 flip_percentage = 100; 
const volatile bool filter_tcp = true;		/* This is a boolean flag to enable filtering of TCP packets */
const volatile bool filter_udp = true;		/* This is a boolean flag to enable filtering of UDP packets */
const volatile bool ingress = false;		/* This is a boolean flag to enable filtering of ingress packets */
const volatile bool egress = true;			/* This is a boolean flag to enable filtering of egress packets */

GADGET_PARAM(ipaddr_v4_filter);
GADGET_PARAM(ipaddr_v6_filter);
GADGET_PARAM(port);
GADGET_PARAM(flip_percentage);
GADGET_PARAM(filter_tcp);
GADGET_PARAM(filter_udp);
GADGET_PARAM(ingress);
GADGET_PARAM(egress);


static __always_inline int rand_bit_flip(struct __sk_buff *skb, __u32 *data_len)
{

    // Ensure the packet has valid length
    if (*data_len < 1) {
        return TC_ACT_OK;
    }

    // Get a random offset and flip a bit
    __u32 random_offset = bpf_get_prandom_u32() % *data_len;
    __u8 byte;

    // Use bpf_skb_load_bytes() to load the byte at the random offset
    if (bpf_skb_load_bytes(skb, random_offset, &byte, sizeof(byte)) < 0) {
        return TC_ACT_OK;  // Error in loading byte, return OK
    }
    
    // Flip a random bit in the byte
    __u8 random_bit = 1 << (bpf_get_prandom_u32() % 8);
    byte ^= random_bit;

    // Use bpf_skb_store_bytes() to store the modified byte back to the packet
    if (bpf_skb_store_bytes(skb, random_offset, &byte, sizeof(byte), 0) < 0) {
        return TC_ACT_OK;  // Error in storing byte, return OK
    }

    return TC_ACT_OK;
}

static __always_inline void swap_src_dst(struct event *event, struct events_map_key *key){
	struct gadget_l4endpoint_t temp;
	temp = event->src;
	event->src = key->dst;
	key->dst = temp;
}

/* This function flips packets based on independent (Bernoulli) probability model 
where each packet is flipped with an independent probabilty for flipping packets */
static int rand_bit_flip_map_update(struct event *event, struct events_map_key *key,
									struct sockets_key *sockets_key_for_md, struct __sk_buff *skb,
                                    __u32 *data_len)
{
	__u32 rand_num = bpf_get_prandom_u32();									// Get a random 32-bit unsigned integer
    // Set the threshold using the flip_percentage
    volatile __u64 threshold = (volatile __u64)(
								(volatile __u64)flip_percentage 
								* (__u64)0xFFFFFFFF
								)/100;										// loss_percentage% of UINT32_MAX
	
	if(ingress == true){
		swap_src_dst(event, key);
	}
	struct event *event_map_val  = bpf_map_lookup_elem(&events_map,key);   /* The events which are stored in the events_map */
	
	if(!event) return TC_ACT_OK;

	if (rand_num <= (u32)threshold)											// Run the code only if the random number is less than the threshold
	{
		if(!event_map_val){
			event->flip_cnt = 1;
			/* Data collection using the socket enricher, we use the key from the map
			to collect information regarding pid, mntns_id, tid, ppid etc */
			sockets_key_for_md->port = key->dst.port;
			struct sockets_value *skb_val = bpf_map_lookup_elem(&gadget_sockets, sockets_key_for_md);
			if (skb_val != NULL)
			{
				event->mntns_id = skb_val->mntns;
				event->pid = skb_val->pid_tgid >> 32;
				event->tid = (__u32)skb_val->pid_tgid;
				event->ppid = skb_val->ppid;
				__builtin_memcpy(&event->comm, skb_val->task, sizeof(event->comm));
				__builtin_memcpy(&event->pcomm, skb_val->ptask, sizeof(event->pcomm));
				event->uid = (__u32)skb_val->uid_gid;
				event->gid = (__u32)(skb_val->uid_gid >> 32);
			}
			bpf_map_update_elem(&events_map,key,event,BPF_NOEXIST);
		} 
		else
		{
			// Increment the the value of flip count by 1. 
			// We use sync fetch and add which is an atomic addition operation
			__sync_fetch_and_add(&event_map_val->flip_cnt, 1);
			bpf_map_update_elem(&events_map,key,event_map_val,BPF_EXIST);
		}
		return rand_bit_flip(skb, data_len);			
	} 
	return TC_ACT_OK;
}


static __always_inline void read_ipv6_address(struct event *event, struct events_map_key *key, struct ipv6hdr *ip6h ){
	bpf_probe_read_kernel(event->src.addr_raw.v6, sizeof(event->src.addr_raw.v6), ip6h->saddr.in6_u.u6_addr8);
	bpf_probe_read_kernel(key->dst.addr_raw.v6, sizeof(key->dst.addr_raw.v6), ip6h->daddr.in6_u.u6_addr8);
}

/* compare_v6_ipaddr_v6 -> compares it with ipaddr_v6 parameter
by converting the 16 bytes of the ip address to 2 __u64 values and comparing them
returns 1 if true and returns 0 if false */
static __always_inline int compare_v6_ipaddr_v6(__u8 v6[]){
	__u128 temp = {0,0};

	 // Convert the first 8 bytes to uint64_t (big-endian)
    for (int i = 0; i < 8; i++) {
        temp.a = (temp.a << 8) | v6[i];
    }

    // Convert the last 8 bytes to uint64_t (big-endian)
    for (int i = 8; i < 16; i++) {
        temp.b = (temp.b << 8) | v6[i];
    }

	if(temp.a == ipaddr_v6_filter.a && temp.b == ipaddr_v6_filter.b){
		return 1;
	}
	 
	return 0;
}

int bit_flip(struct __sk_buff *skb){
    
    struct events_map_key key;						/* This is the key for events_map -> being the target addr,port pair */
	struct sockets_key sockets_key_for_md; 			/* This is for socket enrichement map */
	struct event event ;							/* The sturct to store the information regarding the event */						
    
    event.egress = egress;
	event.ingress = ingress;
	event.netns_id = skb->cb[0]; 					// cb[0] initialized by dispatcher.bpf.c to get the netns
	sockets_key_for_md.netns = event.netns_id;	

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    if (data >= data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
	struct iphdr *ip4h ;
	struct ipv6hdr *ip6h ;

    /* Check if the ethernet headers are invalid if so ignore 
	   the packets, else do the further processing	 */
    if ((void *)(eth + 1)> data_end)
    {
		return TC_ACT_OK; 															// Eth headers incomplete - Letting them pass through the without further processing
    }

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) 									// IPv4 Processing
	{
		ip4h = (struct iphdr *)(eth + 1);

		/* Check if the IPv4 headers are invalid */
		if ((void *)(ip4h + 1) > data_end)
		{
			return TC_ACT_OK;
		}

		event.src.addr_raw.v4 = ip4h->saddr;
		key.dst.addr_raw.v4 = ip4h->daddr;
		event.src.version = key.dst.version = 4;
		sockets_key_for_md.family = SE_AF_INET;

		if (filter_tcp == true && ip4h->protocol == IPPROTO_TCP) 							// Check if packets follow TCP protocol and if we want to flip tcp packets 
		{								
			struct tcphdr *tcph = (struct tcphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));
			if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;  								// Packet is too short, ignore
			event.src.proto_raw = key.dst.proto_raw = IPPROTO_TCP;
			event.src.port = bpf_ntohs(tcph->source);										// Extract source and destination ports from the TCP header	
			if(skb->pkt_type == SE_PACKET_HOST)
				key.dst.port = bpf_ntohs(tcph->dest);
			else
				key.dst.port = bpf_ntohs(tcph->source);
			sockets_key_for_md.proto = IPPROTO_TCP;
		} 
		else if (filter_udp == true && ip4h->protocol == IPPROTO_UDP )
		{										
			struct udphdr *udph = (struct udphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));
			if ((void *)(udph + 1) > data_end) return TC_ACT_OK;  								// Packet is too short
			event.src.port = bpf_ntohs(udph->source);										// Extract source and destination ports from the UDP header
			if(skb->pkt_type == SE_PACKET_HOST)
				key.dst.port = bpf_ntohs(udph->dest);
			else
				key.dst.port = bpf_ntohs(udph->source);
			event.src.proto_raw = key.dst.proto_raw = IPPROTO_UDP;
			sockets_key_for_md.proto = IPPROTO_UDP;
		}
		else 
		{
			return TC_ACT_OK;
		}
	}	
	else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) 									// IPv6 Processing
	{
		ip6h = (struct ipv6hdr *)(eth + 1);

		/* Check if the IPv6 headers are invalid */
		if ((void *)(ip6h + 1)  > data_end)
		{
			return TC_ACT_OK;
		}
		event.src.version = key.dst.version = 6;
		sockets_key_for_md.family = SE_AF_INET6;
		
		// Check if packets follow TCP protocol
		if (filter_tcp == true && ip6h->nexthdr == IPPROTO_TCP) 
		{
			read_ipv6_address(&event, &key, ip6h);

			struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)  return TC_ACT_OK; 							 // Packet is too short, ignore
			event.src.proto_raw = key.dst.proto_raw = IPPROTO_TCP;
			event.src.port = bpf_ntohs(tcph->source);
			if(skb->pkt_type == SE_PACKET_HOST)
				key.dst.port = bpf_ntohs(tcph->dest);
			else
				key.dst.port = bpf_ntohs(tcph->source);
			sockets_key_for_md.proto = IPPROTO_TCP;
		} 
		else if (filter_udp == true && ip6h->nexthdr == IPPROTO_UDP)
		{
			struct udphdr *udph = (struct udphdr *)(ip6h + 1);
			if ((void *)(udph + 1) > data_end)  return TC_ACT_OK;  							 // Packet is too short, ignore
			event.src.port = bpf_ntohs(udph->source);
			if(skb->pkt_type == SE_PACKET_HOST)
				key.dst.port = bpf_ntohs(udph->dest);
			else
				key.dst.port = bpf_ntohs(udph->source);
			event.src.proto_raw = key.dst.proto_raw = IPPROTO_UDP;
			sockets_key_for_md.proto = IPPROTO_UDP;
		}
		else
		{
			return TC_ACT_OK;
		}
	} 
	else
	{
		return TC_ACT_OK;	// Letting them pass through the without further processing
	}

    /* 
		Possible filtering cases:

		IPv4   IPv6   Port
		y		y		y
		y		n		y
		y		y		n
		y		n		n
		n		y		y
		.....
	 */
	event.timestamp_raw = bpf_ktime_get_boot_ns();

	__u8 v4_set = 0;
	__u8 v6_set = 0;
	__u8 port_set = 0;

	if (ipaddr_v4_filter != 0) v4_set = 1;
	if (ipaddr_v6_filter.a != 0 || ipaddr_v6_filter.b != 0) v6_set = 1;
	if (port != 0) port_set = 1;

	__u8 case_id = (__u8)((v4_set << 2) | (v6_set << 1) | port_set);


    // Calculate the length of the packet data as an unsigned integer
    __u32 data_len = (__u32)(data_end - data);

	/* We always check based on the target ip filter. So in case of egress, our ip filter drops packets 
	going to that IP i.e whose destination is that
	
	in case of ingress, we filter packets coming from that IP , so we swap the src and dst for ingress do the check
	and swap it back before the map operations are performed */

	if(ingress == true){
		swap_src_dst(&event, &key);
	}

switch(case_id) 
	{
        case 7: // IPv4, IPv6, Port (0b111)
			if(((key.dst.version == 4 && ipaddr_v4_filter == key.dst.addr_raw.v4)
			 || (key.dst.version == 6 && compare_v6_ipaddr_v6(key.dst.addr_raw.v6)))
			 &&  port == key.dst.port ){
				return rand_bit_flip_map_update(&event, &key, &sockets_key_for_md, skb, &data_len);
			}
            break;
        case 6: // IPv4, IPv6, No Port (0b110)
			if((key.dst.version == 4 &&  ipaddr_v4_filter == key.dst.addr_raw.v4)
			 || (key.dst.version == 6 && compare_v6_ipaddr_v6(key.dst.addr_raw.v6))){
				return rand_bit_flip_map_update(&event, &key, &sockets_key_for_md, skb, &data_len);
			}
            break;
        case 5: // IPv4, No IPv6, Port (0b101)
			if(key.dst.version == 4 && ipaddr_v4_filter == key.dst.addr_raw.v4 && port == key.dst.port){
				return rand_bit_flip_map_update(&event, &key, &sockets_key_for_md, skb, &data_len);
			}
            break;
        case 4: // IPv4, No IPv6, No Port (0b100)
			if(key.dst.version == 4 && ipaddr_v4_filter == key.dst.addr_raw.v4){
				return rand_bit_flip_map_update(&event, &key, &sockets_key_for_md, skb, &data_len);
			}
            break;
        case 3: // No IPv4, IPv6, Port (0b011)
			if(key.dst.version == 6 && compare_v6_ipaddr_v6(key.dst.addr_raw.v6) && port == key.dst.port){
				return rand_bit_flip_map_update(&event, &key, &sockets_key_for_md, skb, &data_len);
			}
            break;
        case 2: // No IPv4, IPv6, No Port (ob010)
			if(key.dst.version == 6 && compare_v6_ipaddr_v6(key.dst.addr_raw.v6)){
				return rand_bit_flip_map_update(&event, &key, &sockets_key_for_md, skb, &data_len);
			}
            break;
        case 1: // No IPv4, No IPv6, Port (0b001)
			if(port == key.dst.port){
				return rand_bit_flip_map_update(&event, &key, &sockets_key_for_md, skb, &data_len);
			}
            break;
        case 0: // No IPv4, No IPv6, No Port (0b000)
			return rand_bit_flip_map_update(&event, &key, &sockets_key_for_md, skb, &data_len);
            break;
		default:
			// "default case : something wrong with the logic"
			return TC_ACT_OK;
    }
	
	return TC_ACT_OK;

}


SEC("classifier/egress/bit_flip")
int egress_bit_flip(struct __sk_buff *skb) {
    if(egress == true)
        return bit_flip(skb);
    else
        return TC_ACT_OK;
}

SEC("classifier/ingress/bit_flip")
int ingress_bit_flip(struct __sk_buff *skb) {
    if(ingress == true)
        return bit_flip(skb);
    else
        return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";	