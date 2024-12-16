#ifndef GADGET_DNS_COMMON_H
#define GADGET_DNS_COMMON_H

#define TASK_COMM_LEN 16
#define MAX_STRING_SIZE 4096

struct event_t {
	// Keep netns at the top: networktracer depends on it
	__u32 netns;

	__u64 timestamp;
	__u64 mount_ns_id;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u8 comm[TASK_COMM_LEN];
	__u8 pcomm[TASK_COMM_LEN];

	union {
		__u8 saddr_v6[16];
		__u32 saddr_v4;
	};
	union {
		__u8 daddr_v6[16];
		__u32 daddr_v4;
	};
	__u16 af; // AF_INET or AF_INET6

	// Internet protocol and port numbers.
	__u16 sport;
	__u16 dport;
	__u16 dns_off; // DNS offset in the packet
	__u8 proto;

	unsigned char pkt_type;
	__u64 latency_ns; // Set only if the packet is a response and pkt_type is 0 (Host).

#ifdef WITH_LONG_PATHS
	__u8 cwd[MAX_STRING_SIZE];
	__u8 exepath[MAX_STRING_SIZE];
#endif
};

#define MAX_PACKET (1024 * 9) // 9KB

#endif
