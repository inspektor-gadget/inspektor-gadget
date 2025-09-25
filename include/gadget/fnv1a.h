/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FNV1A_H
#define __FNV1A_H

#include <bpf/bpf_helpers.h>

// FNV-1a hash functions
// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
//
// Original implementation in the public domain:
// https://github.com/lcn2/fnv

#define FNV1_32_PRIME ((u32)0x01000193)
#define FNV1_32_INIT ((u32)0x811c9dc5)

#define FNV1_64_PRIME ((u64)0x00000100000001b3)
#define FNV1_64_INIT ((u64)0xcbf29ce484222325)

static __always_inline u32 fnv_32a_init()
{
	return FNV1_32_INIT;
}

static __always_inline u64 fnv_64a_init()
{
	return FNV1_64_INIT;
}

// Ingest integers in little-endian order, as it is the most common usage
// for FNV-1a.

#define DEFINE_FNV_UPDATE(fn_name, hash_type, value_type, value_size, prime)   \
	static __always_inline void fn_name(hash_type *hash, value_type value) \
	{                                                                      \
		for (int i = 0; i < value_size; i++) {                         \
			*hash ^= (value >> (i * 8)) & 0xff;                    \
			*hash *= prime;                                        \
		}                                                              \
	}

// 32-bit hash functions
DEFINE_FNV_UPDATE(fnv_32a_update_u64, u32, u64, sizeof(u64), FNV1_32_PRIME)
DEFINE_FNV_UPDATE(fnv_32a_update_u32, u32, u32, sizeof(u32), FNV1_32_PRIME)
DEFINE_FNV_UPDATE(fnv_32a_update_u16, u32, u16, sizeof(u16), FNV1_32_PRIME)
DEFINE_FNV_UPDATE(fnv_32a_update_u8, u32, u8, sizeof(u8), FNV1_32_PRIME)

// 64-bit hash functions
DEFINE_FNV_UPDATE(fnv_64a_update_u64, u64, u64, sizeof(u64), FNV1_64_PRIME)
DEFINE_FNV_UPDATE(fnv_64a_update_u32, u64, u32, sizeof(u32), FNV1_64_PRIME)
DEFINE_FNV_UPDATE(fnv_64a_update_u16, u64, u16, sizeof(u16), FNV1_64_PRIME)
DEFINE_FNV_UPDATE(fnv_64a_update_u8, u64, u8, sizeof(u8), FNV1_64_PRIME)

#undef DEFINE_FNV_UPDATE

#endif /* __FNV1A_H */
