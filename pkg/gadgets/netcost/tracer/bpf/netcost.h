#ifndef __NETCOST_BPF__
#define __NETCOST_BPF__

#include <linux/bpf.h>

struct cidr_stats {
	__u64 bytes_recv;
	__u64 bytes_sent;
	__u64 packets_sent;
	__u64 packets_recv;
};

#endif
