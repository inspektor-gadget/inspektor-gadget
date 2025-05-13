/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

// This file defines some helpers to apply packet filters to a skb.

#ifndef PACKETFILTER_H
#define PACKETFILTER_H

// GADGET_PF is used to define a new packet filter with a given name. The name is optional.
#define GADGET_PF(name)                                                      \
	static __noinline bool gadget_pf_##name(void *_skb, void *__skb,     \
						void *___skb, void *data,    \
						void *data_end)              \
	{                                                                    \
		return data != data_end && _skb == __skb && __skb == ___skb; \
	}

// Count number of arguments
#define _ARG_N(_1, _2, _3, _4, N, ...) N
#define COUNT_ARGS(...) _ARG_N(__VA_ARGS__, 4, 3, 2, 1)

// Dispatch to the correct macro based on argument count
#define _GADGET_PF_MATCHES_0() \
	_Static_assert(0, "gadget_pf_matches: wrong number of arguments")

#define _GADGET_PF_MATCHES_1(ARG1) \
	_Static_assert(0, "gadget_pf_matches: wrong number of arguments")

#define _GADGET_PF_MATCHES_2(ARG1, ARG2) \
	_Static_assert(0, "gadget_pf_matches: wrong number of arguments")

#define _GADGET_PF_MATCHES_3(skb, data, data_end) \
	gadget_pf_matches_impl(, skb, data, data_end)

#define _GADGET_PF_MATCHES_4(name, skb, data, data_end) \
	gadget_pf_matches_impl(name, skb, data, data_end)

// Macro overloading dispatcher
#define _GADGET_PF_MATCHES_CHOOSER2(count) _GADGET_PF_MATCHES_##count
#define _GADGET_PF_MATCHES_CHOOSER1(count) _GADGET_PF_MATCHES_CHOOSER2(count)
#define _GADGET_PF_MATCHES_CHOOSER(...) \
	_GADGET_PF_MATCHES_CHOOSER1(COUNT_ARGS(__VA_ARGS__))

#define gadget_pf_matches(...) \
	_GADGET_PF_MATCHES_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

// the redundant skb args reserve some registers (R1-R3) for the cbpf2ebpf conversion
#define gadget_pf_matches_impl(name, skb, data, data_end) \
	gadget_pf_##name(skb, skb, skb, data, data_end)

#endif