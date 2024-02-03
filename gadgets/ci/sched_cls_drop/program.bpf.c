#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

SEC("classifier/egress/drop")
int egress_drop(struct __sk_buff *skb)
{
	return TC_ACT_SHOT;
}

SEC("classifier/ingress/drop")
int ingress_drop(struct __sk_buff *skb)
{
	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
