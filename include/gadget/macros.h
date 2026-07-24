/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __MACROS_H
#define __MACROS_H

// Internal helpers to concatenate two tokens. Do not use directly
#define __CONCAT_IMPL(x, y) x##y
#define __CONCAT(x, y) __CONCAT_IMPL(x, y)

// Internal helpers to count the number of arguments. Do not use directly
#define __VA_NARGS_IMPL(_1, _2, _3, _4, N, ...) N
#define __VA_NARGS(...) __VA_NARGS_IMPL(__VA_ARGS__, 4, 3, 2, 1)

// Internal helpers to expand the snapshotter's programs. Do not use directly
#define __GADGET_ITER_PROGRAMS_EXPAND_1(name, type, programName1)    \
	const void *gadget_iter_##name##___##type##___##programName1 \
		__attribute__((unused));
#define __GADGET_ITER_PROGRAMS_EXPAND_2(name, type, programName1,                   \
					programName2)                               \
	const void *                                                                \
		gadget_iter_##name##___##type##___##programName1##___##programName2 \
		__attribute__((unused));
#define __GADGET_ITER_PROGRAMS_EXPAND_3(name, type, programName1,                                      \
					programName2, programName3)                                    \
	const void *                                                                                   \
		gadget_iter_##name##___##type##___##programName1##___##programName2##___##programName3 \
		__attribute__((unused));
#define __GADGET_ITER_PROGRAMS_EXPAND(name, type, nargs, ...) \
	__CONCAT(__GADGET_ITER_PROGRAMS_EXPAND_, nargs)       \
	(name, type, __VA_ARGS__)
#define __GADGET_ITER_IMPL(name, type, ...)                                \
	__GADGET_ITER_PROGRAMS_EXPAND(name, type, __VA_NARGS(__VA_ARGS__), \
				      __VA_ARGS__)

// Public macros. Use these in your code
// Keep this aligned with pkg/gadgets/run/types/metadata.go

// Internal: prefix every IG decl tag with "ig:". Do not use directly.
#define __ig_tag(s) __attribute__((btf_decl_tag("ig:" s)))

// GADGET_MAP_ONLY_IF gates a map on an expression. Place it on a map
// definition (in .maps). The map is created only when <expr> (an expr-lang
// expression over params, e.g. "params.collect_ustack") evaluates to true;
// otherwise the map is not created and every instruction referencing it is
// poisoned. Those references MUST therefore be dead code, i.e. guarded by (a
// superset of) the same condition. <expr> MUST be a string literal and must be
// a function of the same const volatile param(s) that guard the map's C users;
// it must NOT depend on kallsyms.* (put symbol preconditions in GADGET_ASSERT).
#define GADGET_MAP_ONLY_IF(expr) __ig_tag("only_if:" expr)

// GADGET_PROG_ATTACH_TO selects a program's attach target. Place it on a
// program (function) definition, immediately before the return type. <expr>
// (an expr-lang expression over params.*, kallsyms.*, program.disabled) MUST
// return a string: a kernel symbol to attach to, or program.disabled to skip
// the program. <expr> MUST be a string literal.
#define GADGET_PROG_ATTACH_TO(expr) __ig_tag("attach_to:" expr)

// GADGET_ASSERT declares a standalone load-time precondition. It is NOT
// attached to any param; it emits a throwaway declaration carrying the tag.
// <name> is an identifier used only as a diagnostic label and to keep the
// symbol unique. <expr> (over params.*, kallsyms.* and defines) is evaluated
// once after params are resolved; if it is false, the gadget fails to load
// with an error naming <name> and quoting <expr>. <expr> MUST be a string
// literal returning bool. Place at file scope.
#define GADGET_ASSERT(name, expr)                    \
	const int __ig_assert_##name __attribute__(( \
		unused, btf_decl_tag("ig:assert:" #name ":" expr))) = 0;

// GADGET_EXPR_DEFINE declares a gadget-scoped named value added to the expr
// environment, so every expression declared after it can reference <name>.
// It emits a throwaway declaration carrying the tag. <expr> (over params.*,
// kallsyms.*, program.disabled and earlier defines) is evaluated once, in
// source order. <expr> MUST be a string literal. Place at file scope.
#define GADGET_EXPR_DEFINE(name, expr)               \
	const int __ig_define_##name __attribute__(( \
		unused, btf_decl_tag("ig:define:" #name ":" expr))) = 0;

// GADGET_TRACER is used to define a tracer. Currently only one tracer per eBPF object is allowed.
// name is the tracer's name
// map_name is the name of the perf event array or ring buffer maps used to send events to user
// space
// event_type is the name of the structure that describes the event
#define GADGET_TRACER(name, map_name, event_type)                        \
	const void *gadget_tracer_##name##___##map_name##___##event_type \
		__attribute__((unused));                                 \
	const struct event_type *__gadget_tracer_type_##name             \
		__attribute__((unused));

// GADGET_PARAM marks a const volatile variable as a user-settable parameter.
// Users of Inspektor Gadget can set these values from userspace. It emits a
// throwaway declaration carrying an "ig:param:<name>" decl tag; the ebpf
// operator reads the tag and registers <name> as a parameter. The legacy
// gadget_param_<name> name-encoding is still read for pre-built gadget images
// (see pkg/operators/ebpf/types.go), so old images keep working.
#define GADGET_PARAM(name)          \
	const int __ig_param_##name \
		__attribute__((unused, btf_decl_tag("ig:param:" #name))) = 0;

// GADGET_SNAPSHOTTER is used to define a snapshotter:
// name is the snapshotter's name
// type is the name of the structure that describes each element in a snapshot
// ... is the variadic list of programs (min 1, max 3) that generate a snapshot
// The snapshotter's output will be the union of the snapshots generated by the programs
// Deprecated: please use GADGET_ITER() instead
#define GADGET_SNAPSHOTTER(name, type, ...)              \
	const struct type *unusedevent_##name##___##type \
		__attribute__((unused));                 \
	__GADGET_ITER_IMPL(name, type, __VA_ARGS__)

// GADGET_ITER is used to define an iterator:
// name is the iterator's name
// type is the name of the structure that describes each element in an iterator
// ... is the variadic list of programs (min 1, max 3) that generate an iterator
// The iterator's output will be the union of the entries returned by the individual iter programs
#define GADGET_ITER(name, type, ...)                     \
	const struct type *unusedevent_##name##___##type \
		__attribute__((unused));                 \
	__GADGET_ITER_IMPL(name, type, __VA_ARGS__)

// GADGET_MAPITER defines maps that IG should periodically fetch into data sources
// - name is the name of the map iterator
// - mapname is the name of the hash map used to send events to user space.
//
// It emits a throwaway declaration carrying an ig:mapiter:<name>___<mapname>
// decl tag. The <name>___<mapname> value keeps the two identifiers that the old
// gadget_mapiter_<name>___<mapname> symbol encoded; IG resolves the map by name.
#define GADGET_MAPITER(name, mapname)                                   \
	const int __ig_mapiter_##name##___##mapname                     \
		__attribute__((unused, btf_decl_tag("ig:mapiter:" #name \
						    "___" #mapname))) = 0;

// GADGET_ITER_TARGET_MAP binds a BPF iter program declared with
// SEC("iter/bpf_map_elem") to the map it should iterate over. The kernel
// requires the target map FD at attach time; this macro tells IG which map
// to pass to bpf_link_create's iter_info.map_fd. Use together with
// GADGET_ITER(name, event_type, prog_name).
//
// Example:
//
//   struct {
//       __uint(type, BPF_MAP_TYPE_LRU_HASH);
//       __uint(max_entries, 4096);
//       __type(key,   struct mykey);
//       __type(value, struct myval);
//       __uint(pinning, LIBBPF_PIN_BY_NAME);
//   } my_pinned_map SEC(".maps");
//
//   GADGET_ITER(my_iter, my_event, dump_my_map);
//   GADGET_ITER_TARGET_MAP(dump_my_map, my_pinned_map);
//
//   SEC("iter/bpf_map_elem")
//   int dump_my_map(struct bpf_iter__bpf_map_elem *ctx) { ... }
//
// - prog_name is the BPF iter program (SEC("iter/bpf_map_elem")).
// - mapname is the map declared in this object (commonly LIBBPF_PIN_BY_NAME).
//
// It emits a throwaway declaration carrying an
// ig:iter_target_map:<prog_name>___<mapname> decl tag (both identifiers are
// preserved from the old gadget_mapelem_iter_target_<prog>___<map> symbol).
#define GADGET_ITER_TARGET_MAP(prog_name, mapname)                           \
	const int __ig_iter_target_map_##prog_name##___##mapname             \
		__attribute__((unused,                                       \
			       btf_decl_tag("ig:iter_target_map:" #prog_name \
					    "___" #mapname))) = 0;

// GADGET_SK_TARGET_MAP binds an sk_skb or sk_msg program to the sockmap or
// sockhash where it should be attached.
#define GADGET_SK_TARGET_MAP(prog_name, mapname)                    \
	const void *gadget_sk_prog_target_##prog_name##___##mapname \
		__attribute__((unused));

#endif /* __MACROS_H */
