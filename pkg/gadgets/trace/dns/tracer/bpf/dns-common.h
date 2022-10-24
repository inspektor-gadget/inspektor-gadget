#ifndef GADGET_DNS_COMMON_H
#define GADGET_DNS_COMMON_H

// Max DNS name length: 255
// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
#define MAX_DNS_NAME 255

struct event_t {
	union {
		__u32 saddr_v4;
		unsigned __int128 saddr_v6;
	};
	union {
		__u32 daddr_v4;
		unsigned __int128 daddr_v6;
	};
	__u32 af; // AF_INET or AF_INET6

	char name[MAX_DNS_NAME];
	unsigned char pkt_type;
	unsigned short qtype;
};

#endif
