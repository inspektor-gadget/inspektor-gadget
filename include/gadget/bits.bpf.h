/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BITS_BPF_H
#define __BITS_BPF_H

static __always_inline u64 log2(u32 v)
{
	u32 shift, r;

	r = (v > 0xFFFF) << 4;
	v >>= r;
	shift = (v > 0xFF) << 3;
	v >>= shift;
	r |= shift;
	shift = (v > 0xF) << 2;
	v >>= shift;
	r |= shift;
	shift = (v > 0x3) << 1;
	v >>= shift;
	r |= shift;
	r |= (v >> 1);

	return r;
}

//get_slot_idx returns the index of the slot to display on the histogram.
static __always_inline u64 get_slot_idx(u64 v)
{
	if (v == 0)
		return 0;

	u32 hi = v >> 32;
	return hi ? log2(hi) + 33 : log2(v) + 1;
}

#endif /* __BITS_BPF_H */
