#ifndef GADGET_DNS_COMMON_H
#define GADGET_DNS_COMMON_H

// Max DNS name length: 255
// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
#define MAX_DNS_NAME 255

struct event_t {
	char name[MAX_DNS_NAME];
	unsigned char pkt_type;
	unsigned short qtype;
};

#endif
