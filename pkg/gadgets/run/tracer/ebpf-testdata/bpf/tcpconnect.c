// Based on: https://github.com/solo-io/bumblebee/blob/main/examples/tcpconnect/tcpconnect.c
// Based on: https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnect.c
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

typedef u32 ipv4_addr;

struct dimensions_t {
	ipv4_addr saddr;
	ipv4_addr daddr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dimensions_t);
	__type(value, u64);
} events_hash_counter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct dimensions_t);
} print_events_ring_counter SEC(".maps");

static __always_inline int
enter_tcp_connect(struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	bpf_printk("enter called");

	bpf_printk("enter: setting sk for tid: %u", tid);
	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;

	__u32 saddr;
	__u32 daddr;
	u64 val;
	u64 *valp;
	struct dimensions_t hash_key = {};

	bpf_printk("exit: getting sk for tid: '%u', ret is: '%d'", tid, ret);
	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp) {
		bpf_printk("exit: no pointer for tid, returning: %u", tid);
		return 0;
	}
	sk = *skpp;

	bpf_printk("exit: found sk for tid: %u", tid);
	BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
	hash_key.saddr = saddr;
	hash_key.daddr = daddr;

	// Set Hash map
	valp = bpf_map_lookup_elem(&events_hash_counter, &hash_key);
	if (!valp) {
		bpf_printk("no entry for {saddr: %u, daddr: %u}", hash_key.saddr, hash_key.daddr);
		val = 1;
	}
	else {
		bpf_printk("found existing value '%llu' for {saddr: %u, daddr: %u}", *valp, hash_key.saddr, hash_key.daddr);
		val = *valp + 1;
	}
	bpf_map_update_elem(&events_hash_counter, &hash_key, &val, 0);
	bpf_map_delete_elem(&sockets, &tid);

	// Set Ringbuffer
	struct dimensions_t *ring_val;

	ring_val = bpf_ringbuf_reserve(&print_events_ring_counter, sizeof(struct dimensions_t), 0);
	if (!ring_val) {
		return 0;
	}

	ring_val->saddr = saddr;
	ring_val->daddr = daddr;

	bpf_ringbuf_submit(ring_val, 0);

	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_e, struct sock *sk)
{
	return enter_tcp_connect(sk);
}


SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_x, int ret)
{
	return exit_tcp_connect(ret);
}