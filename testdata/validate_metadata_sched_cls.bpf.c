#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

SEC("classifier/egress/drop")
int egress_drop(struct __sk_buff *skb)
{
	return -1; // TC_ACT_SHOT
}