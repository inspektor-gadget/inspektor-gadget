#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define NAME_MAX 255

const volatile int param;
const volatile int param2;

GADGET_PARAM(param);
// GADGET_PARAM(param2); intentionally ommited

char LICENSE[] SEC("license") = "GPL";
