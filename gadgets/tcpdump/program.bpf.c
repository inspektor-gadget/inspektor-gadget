#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/buffer.h>
#include <gadget/filter.h>

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>

struct packet_event_t {
	u64 timestamp;
	u8 packet_type;
	u8 first_layer;
	u16 l3_protocol;
	u32 ifindex;
	u32 payload_len;
	u32 packet_size;
	struct gadget_process proc;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 25);
} packets SEC(".maps");

GADGET_TRACER(packets, packets, packet_event_t);

static __noinline bool gadget_pf_main(void *_skb, void *__skb, void *___skb, void *data, void *data_end) {
	return data != data_end && _skb == __skb && __skb == ___skb;
}

#define MAX_PKT_LEN 1500

static __always_inline int handle(struct __sk_buff *skb) {
	if (!gadget_pf_main((void*)skb, (void*)skb, (void*)skb, (void *)(long)skb->data, (void *)(long)skb->data_end)) {
		return 0;
	}

	struct sockets_value *skb_val = gadget_socket_lookup(skb);
	if (gadget_should_discard_data_by_skb(skb_val))
		return 0;

	void *packet = NULL;
	struct packet_event_t *event;

	packet = gadget_reserve_buf(&packets, sizeof(*event) + MAX_PKT_LEN);
	if (!packet) return 0;
	event = (struct packet_event_t *)packet;
	if (!event) return 0;

	__builtin_memset(event, 0, sizeof(*event));

	__u64 len = skb->len;
	event->packet_size = len;

	if (len > MAX_PKT_LEN)
		len = MAX_PKT_LEN;

	if (len > 0) {
		u8* data = (u8*)(event + 1);
		// bpf_skb_load_bytes(skb, 0, data, len); // verifier doesn't like this
		bpf_probe_read_kernel(data, len, (void*)(long)skb->data);
	}

	event->payload_len = len;
	event->timestamp = bpf_ktime_get_ns();
	event->ifindex = skb->ifindex;

	if (skb_val != NULL) {
		// Enrich event with process metadata
		gadget_process_populate_from_socket(skb_val, &event->proc);
	}

	gadget_submit_buf(NULL, NULL, packet, 0);
	return 0;
}

SEC("classifier/ingress/main")
int ingress_main(struct __sk_buff *skb) {
	bpf_skb_pull_data(skb, 0);
	return handle(skb);
}

SEC("classifier/egress/main")
int egress_main(struct __sk_buff *skb) {
	bpf_skb_pull_data(skb, 0);
	return handle(skb);
}

char _license[] SEC("license") = "GPL";
