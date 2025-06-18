#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>

enum direction {
	EGRESS = 0,
	INGRESS = 1,
};

struct event {
	enum direction dir_raw;
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(exec, events, event);

void handle(void *ctx, enum direction dir)
{
	struct event *event;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return;

	event->dir_raw = dir;
	gadget_submit_buf(ctx, &events, event, sizeof(*event));
}

SEC("classifier/egress/drop")
int egress_drop(struct __sk_buff *skb)
{
	handle(skb, EGRESS);
	return TC_ACT_UNSPEC;
}

SEC("classifier/ingress/drop")
int ingress_drop(struct __sk_buff *skb)
{
	handle(skb, INGRESS);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
