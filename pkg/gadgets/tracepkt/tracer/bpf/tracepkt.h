#ifndef GADGET_TRACEPKT_COMMON_H
#define GADGET_TRACEPKT_COMMON_H

#ifndef IFNAMSIZ
#define	IFNAMSIZ	16
#endif

// Limits come from:
// include/uapi/linux/netfilter/nf_tables.h
// But reduce them so they fit on the stack
// TODO: move large on stack variables into BPF per-cpu array map.

#ifndef TABLENAMESIZ
#define TABLENAMESIZ 64
#endif

#ifndef CHAINNAMESIZ
#define CHAINNAMESIZ 64
#endif

#ifndef COMMENTSIZ
#define COMMENTSIZ 8
#endif

struct event_t {
	char ifname_in[IFNAMSIZ];
	char ifname_out[IFNAMSIZ];
	char tablename[TABLENAMESIZ];
	char chainname[CHAINNAMESIZ];
	char comment[COMMENTSIZ];
	long long unsigned int netns_in;
	long long unsigned int netns_out;
	long long unsigned int rulenum;
	int ifindex_in;
	int ifindex_out;
};

#endif
