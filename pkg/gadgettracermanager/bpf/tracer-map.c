#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#define PIN_CUSTOM_NS 3

/* This is a key/value store with the keys being the cgroupid
 * and the values are ignored.
 */
struct bpf_map_def SEC("maps/cgroupid_set") cgroupid_set = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u32),
	.max_entries = 128,
	.pinning = PIN_CUSTOM_NS,
	.namespace = "gadget-tracers",
};
