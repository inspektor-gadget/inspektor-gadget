// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation by the CGO compiler

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8 for more details
 */
#include <linux/types.h>
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <uapi/linux/bpf.h>
#include <linux/kconfig.h>
#include <linux/version.h>

#undef container_of
#include <bpf_helpers.h>

struct bpf_map_def SEC("maps") mntns_set = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(uint64_t),    // mntns
  .value_size = sizeof(uint32_t),  // ignored
  .max_entries = 128,
};

char LICENSE[] SEC("license") = "GPL";
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
