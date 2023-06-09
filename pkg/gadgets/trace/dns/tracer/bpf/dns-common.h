#ifndef GADGET_DNS_COMMON_H
#define GADGET_DNS_COMMON_H

// Max DNS name length: 255
// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
#define MAX_DNS_NAME 255

#define TASK_COMM_LEN	16

// Maximum number of A or AAAA answers to include in the DNS event.
// The DNS reply could have more answers than this, but the additional
// answers won't be sent to userspace.
#define MAX_ADDR_ANSWERS 8

struct event_t {
	__u64 timestamp;
	__u64 mount_ns_id;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u8 task[TASK_COMM_LEN];

	union {
		__u8 saddr_v6[16];
		__u32 saddr_v4;
	};
	union {
		__u8 daddr_v6[16];
		__u32 daddr_v4;
	};
	__u16 af; // AF_INET or AF_INET6

	__u16 id;
	unsigned short qtype;

	// qr says if the dns message is a query (0), or a response (1)
	unsigned char qr;
	unsigned char pkt_type;
	unsigned char rcode;

	__u8 name[MAX_DNS_NAME];

	__u16 ancount;
	__u16 anaddrcount;
	__u8 anaddr[MAX_ADDR_ANSWERS][16]; // Either IPv4-mapped-IPv6 (A record) or IPv6 (AAAA record) addresses.
};

#endif
