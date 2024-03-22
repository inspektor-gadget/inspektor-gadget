/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __MACROS_H
#define __MACROS_H

// Keep this aligned with pkg/gadgets/run/types/metadata.go

// GADGET_TRACER is used to define a tracer. Currently only one tracer per eBPF object is allowed.
// name is the tracer's name
// map_name is the name of the perf event array or ring buffer maps used to send events to user
// space
// event_type is the name of the structure that describes the event
#define GADGET_TRACER(name, map_name, event_type) \
	const void *gadget_tracer_##name##___##map_name##___##event_type __attribute__((unused)); \
	const struct event_type *__gadget_tracer_type_##name __attribute__((unused));

// GADGET_TOPPER is used to define a topper. Currently only one topper per eBPF object is allowed.
// name is the topper's name
// map_name is the name of the hash map used to send events to user space
#define GADGET_TOPPER(name, map_name) \
	const void *gadget_topper_##name##___##map_name __attribute__((unused));

// GADGET_PARAM is used to indicate that a given variable is used as a parameter.
// Users of Inspektor Gadget can set these values from userspace
#define GADGET_PARAM(name) \
	const void * gadget_param_##name __attribute__((unused));

// GADGET_SNAPSHOTTER is used to mark a struct as being produced by a snapshotter gadget.
#define GADGET_SNAPSHOTTER(name, type) \
	const void *gadget_snapshotter_##name##___##type __attribute__((unused)); \
	const struct type *unusedevent_##name##___##type __attribute__((unused));

#ifndef PROFILER_MAX_SLOTS
#define PROFILER_MAX_SLOTS 27
#endif /* !PROFILER_MAX_SLOTS */

// hist_value is used as value for profiler hash map.
struct hist_value {
	__u32 slots[PROFILER_MAX_SLOTS];
};

const struct hist_value *unused___hist_value __attribute__((unused));

// GADGET_PROFILER is used to define a profiler:
// - name is the tracer name.
// - hist_name is the name of the hash map used to send events to user space.
// - hist_key_type is the type of map key.
#define GADGET_PROFILER(name, hist_name, hist_key_type) \
	const void *gadget_profiler_##name##___##hist_name##___##hist_key_type##___hist_value __attribute__((unused)); \
	const struct hist_key_type *unusedevent_##name##___##hist_key_type __attribute__((unused));

#endif /* __MACROS_H */
