// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/filesystem.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define PATH_MAX 4096
#define TASK_COMM_LEN 16

enum type {
	unknown,
	dnotify,
	inotify,
	fanotify,
	fa_resp,
};

enum fa_response {
	na = 0,
	allow = 0x01, // FAN_ALLOW
	deny = 0x02, // FAN_DENY
	interrupted = 3, // tracee interrupted (state != FAN_EVENT_ANSWERED)
	// FAN_AUDIT and FAN_INFO not handled
};

struct enriched_event {
	enum type type;

	__u32 tracee_pid;
	__u32 tracee_tid;
	__u8 tracee_comm[TASK_COMM_LEN];
	__u64 tracee_mntns_id;

	__u32 tracer_pid;
	__u32 tracer_tid;
	__u8 tracer_comm[TASK_COMM_LEN];
	gadget_mntns_id mntns_id;

	__u32 prio;

	__u32 fa_type;
	__u32 fa_mask;
	__u32 fa_pid;
	__u32 fa_flags;
	__u32 fa_f_flags;

	__s32 i_wd;
	__u32 i_mask;
	__u32 i_cookie;
	__u32 i_ino;
	__u32 i_ino_dir;

	__u8 name[PATH_MAX];
};
static const struct enriched_event empty_enriched_event = {};

// context for the caller of fsnotify_insert_event
struct fsnotify_insert_event_value {
	enum type type;
	__u32 i_ino;
	__u32 i_ino_dir;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u64); // tgid_pid
	__type(value, struct fsnotify_insert_event_value);
} fsnotify_insert_event_ctx SEC(".maps");

// context for kprobe/kretprobe fsnotify_remove_first_event
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u64); // tgid_pid
	__type(value, void *); // struct fsnotify_group *
} fsnotify_remove_first_event_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *); // struct fsnotify_event *event
	__type(value, struct enriched_event);
	__uint(max_entries, 10240);
} enriched_fsnotify_events SEC(".maps");

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

const volatile u64 tracer_group = 0;
const volatile pid_t tracer_pid = 0;
const volatile pid_t tracee_pid = 0;
const volatile bool inotify_only = false;
const volatile bool fanotify_only = false;
GADGET_PARAM(tracer_group);
GADGET_PARAM(tracer_pid);
GADGET_PARAM(tracee_pid);
GADGET_PARAM(inotify_only);
GADGET_PARAM(fanotify_only);

struct gadget_event {
	gadget_timestamp timestamp;
	enum type type;

	gadget_mntns_id mntns_id;
	__u32 tracer_pid;
	__u32 tracer_tid;
	char tracer_comm[TASK_COMM_LEN];

	gadget_mntns_id tracee_mntns_id;
	__u32 tracee_pid;
	__u32 tracee_tid;
	char tracee_comm[TASK_COMM_LEN];

	__u32 prio;

	// fsnotify masks are defined in an internal API, but duplicated in two user
	// APIs with mostly the same values. A single u32 is used to define the event
	// type but also flags. Some are internal API, some are public API.
	//
	// Internal flags are filtered before sending the mask to userspace:
	// - inotify_mask_to_arg()
	// - FANOTIFY_OUTGOING_EVENTS
	//
	// For detail, see:
	// https://github.com/torvalds/linux/blob/v6.6/include/linux/fsnotify_backend.h#L31-L47
	// https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/inotify.h#L29-L46
	// https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/fanotify.h#L8-L33
	//
	// TODO: Print masks as string
	__u32 fa_mask;
	__u32 i_mask;

	enum fanotify_event_type fa_type;
	__u32 fa_pid;
	__u32 fa_flags;
	__u32 fa_f_flags;
	enum fa_response fa_response;

	__s32 i_wd;
	__u32 i_cookie;
	__u32 i_ino;
	__u32 i_ino_dir;

	char name[PATH_MAX];
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(fsnotify, events, gadget_event);

// Probes for the tracees

SEC("kprobe/inotify_handle_inode_event")
int BPF_KPROBE(inotify_handle_inode_event_e, struct fsnotify_mark *inode_mark,
	       u32 mask, struct inode *inode, struct inode *dir,
	       const struct qstr *name, u32 cookie)
{
	if (!fanotify_only) {
		u64 pid_tgid = bpf_get_current_pid_tgid();
		struct fsnotify_insert_event_value value = {
			.type = inotify,
			.i_ino = BPF_CORE_READ(inode, i_ino),
			.i_ino_dir = BPF_CORE_READ(dir, i_ino),
		};
		// context for fsnotify_insert_event
		bpf_map_update_elem(&fsnotify_insert_event_ctx, &pid_tgid,
				    &value, 0);
	}
	return 0;
}

SEC("kretprobe/inotify_handle_inode_event")
int BPF_KRETPROBE(inotify_handle_inode_event_x, int ret)
{
	if (!fanotify_only) {
		u64 pid_tgid = bpf_get_current_pid_tgid();
		bpf_map_delete_elem(&fsnotify_insert_event_ctx, &pid_tgid);
	}
	return 0;
}

SEC("kprobe/fanotify_handle_event")
int BPF_KPROBE(fanotify_handle_event_e)
{
	if (!inotify_only) {
		u64 pid_tgid = bpf_get_current_pid_tgid();
		struct fsnotify_insert_event_value value = { .type = fanotify };
		// context for fsnotify_insert_event
		bpf_map_update_elem(&fsnotify_insert_event_ctx, &pid_tgid,
				    &value, 0);
	}
	return 0;
}

SEC("kretprobe/fanotify_handle_event")
int BPF_KRETPROBE(fanotify_handle_event_x, int ret)
{
	if (!inotify_only) {
		u64 pid_tgid = bpf_get_current_pid_tgid();
		bpf_map_delete_elem(&fsnotify_insert_event_ctx, &pid_tgid);
	}
	return 0;
}

SEC("kprobe/fsnotify_insert_event")
int BPF_KPROBE(fsnotify_insert_event_e, struct fsnotify_group *group,
	       struct fsnotify_event *event)
{
	u64 pid_tgid;
	struct enriched_event *ee;
	struct fsnotify_insert_event_value *value;
	struct fanotify_event *fae;
	struct inotify_event_info *ine;
	int name_len;
	struct path *p = NULL;

	pid_tgid = bpf_get_current_pid_tgid();

	if (tracee_pid && tracee_pid != pid_tgid >> 32)
		return 0;

	value = bpf_map_lookup_elem(&fsnotify_insert_event_ctx, &pid_tgid);
	if (value) {
		if (inotify_only && value->type != inotify)
			return 0;
		if (fanotify_only && value->type != fanotify)
			return 0;
	} else {
		if (inotify_only || fanotify_only)
			return 0;
	}

	bpf_map_update_elem(&enriched_fsnotify_events, &event,
			    &empty_enriched_event, BPF_NOEXIST);
	ee = bpf_map_lookup_elem(&enriched_fsnotify_events, &event);
	if (!ee)
		return 0;

	ee->tracee_pid = pid_tgid >> 32;
	ee->tracee_tid = (u32)pid_tgid;
	bpf_get_current_comm(&ee->tracee_comm, sizeof(ee->tracee_comm));
	ee->tracee_mntns_id = gadget_get_mntns_id();

	ee->prio = BPF_CORE_READ(group, priority);

	if (value) {
		ee->type = value->type;

		ee->fa_type = -1;

		switch (ee->type) {
		case inotify:
			ine = container_of(event, struct inotify_event_info,
					   fse);
			ee->i_wd = BPF_CORE_READ(ine, wd);
			ee->i_mask = BPF_CORE_READ(ine, mask);
			ee->i_cookie = BPF_CORE_READ(ine, sync_cookie);
			ee->i_ino = value->i_ino;
			ee->i_ino_dir = value->i_ino_dir;

			name_len = BPF_CORE_READ(ine, name_len);
			if (name_len < 0)
				name_len = 0;
			name_len++; // ine->name_len does not include the NULL at the end
			if (name_len > PATH_MAX)
				name_len = PATH_MAX;
			bpf_probe_read_kernel_str(&ee->name, name_len,
						  &ine->name[0]);
			break;

		case fanotify:
			fae = container_of(event, struct fanotify_event, fse);
			ee->fa_mask = BPF_CORE_READ(fae, mask);
			ee->fa_type = BPF_CORE_READ_BITFIELD_PROBED(fae, type);
			ee->fa_pid = BPF_CORE_READ(fae, pid, numbers[0].nr);
			ee->fa_flags =
				BPF_CORE_READ(group, fanotify_data.flags);
			ee->fa_f_flags =
				BPF_CORE_READ(group, fanotify_data.f_flags);

			if (ee->fa_type == FANOTIFY_EVENT_TYPE_PATH)
				p = &container_of(fae,
						  struct fanotify_path_event,
						  fae)
					     ->path;
			else if (ee->fa_type == FANOTIFY_EVENT_TYPE_PATH_PERM)
				p = &container_of(fae,
						  struct fanotify_perm_event,
						  fae)
					     ->path;

			if (p)
				bpf_probe_read_kernel_str(ee->name, PATH_MAX,
							  get_path_str(p));

			break;

		default:
			break;
		}
	}

	// fsnotify_insert_event() might not add the event, but
	// fsnotify_destroy_event() will be called in any cases.
	bpf_map_update_elem(&enriched_fsnotify_events, &event, ee, 0);

	return 0;
}

SEC("kprobe/fsnotify_destroy_event")
int BPF_KPROBE(fsnotify_destroy_event, struct fsnotify_group *group,
	       struct fsnotify_event *event)
{
	u64 pid_tgid;
	struct fsnotify_insert_event_value *value;
	struct fanotify_event *fae;
	struct fanotify_perm_event *fpe;
	short unsigned int state;
	__u32 fa_type;
	struct gadget_event *gadget_event;
	struct enriched_event *ee;

	// handle fanotify perm responses
	if (inotify_only)
		goto out;

	pid_tgid = bpf_get_current_pid_tgid();
	if (tracee_pid && tracee_pid != pid_tgid >> 32)
		goto out;

	value = bpf_map_lookup_elem(&fsnotify_insert_event_ctx, &pid_tgid);
	if (!value || value->type != fanotify)
		goto out;

	fae = container_of(event, struct fanotify_event, fse);
	fa_type = BPF_CORE_READ_BITFIELD_PROBED(fae, type);
	if (fa_type != FANOTIFY_EVENT_TYPE_PATH_PERM)
		goto out;

	fpe = container_of(fae, struct fanotify_perm_event, fae);

	gadget_event = gadget_reserve_buf(&events, sizeof(*gadget_event));
	if (!gadget_event)
		goto out;

	gadget_event->type = fa_resp;
	gadget_event->fa_type = fa_type;
	gadget_event->prio = BPF_CORE_READ(group, priority);

	gadget_event->timestamp = bpf_ktime_get_boot_ns();

	ee = bpf_map_lookup_elem(&enriched_fsnotify_events, &event);
	if (ee) {
		gadget_event->mntns_id = ee->mntns_id;
		gadget_event->tracer_pid = ee->tracer_pid;
		gadget_event->tracer_tid = ee->tracer_tid;
		__builtin_memcpy(gadget_event->tracer_comm, ee->tracer_comm,
				 TASK_COMM_LEN);
	}

	gadget_event->tracee_mntns_id = gadget_get_mntns_id();
	gadget_event->tracee_pid = pid_tgid >> 32;
	gadget_event->tracee_tid = (u32)pid_tgid;
	bpf_get_current_comm(&gadget_event->tracee_comm,
			     sizeof(gadget_event->tracee_comm));

	bpf_probe_read_kernel_str(gadget_event->name, PATH_MAX,
				  get_path_str(&fpe->path));

	gadget_event->fa_mask = BPF_CORE_READ(fae, mask);
	gadget_event->fa_pid = BPF_CORE_READ(fae, pid, numbers[0].nr);
	gadget_event->fa_flags = BPF_CORE_READ(group, fanotify_data.flags);
	gadget_event->fa_f_flags = BPF_CORE_READ(group, fanotify_data.f_flags);

	state = BPF_CORE_READ(fpe, state);
	if (state == FAN_EVENT_ANSWERED) {
		gadget_event->fa_response = BPF_CORE_READ(fpe, response);
		gadget_event->fa_response &= allow | deny;
	} else {
		gadget_event->fa_response = interrupted;
	}

	gadget_submit_buf(ctx, &events, gadget_event, sizeof(*gadget_event));

out:
	// This might be called for unrelated events. This is fine:
	// bpf_map_delete_elem would just ignore events that are not in the
	// map.
	bpf_map_delete_elem(&enriched_fsnotify_events, &event);
	return 0;
}

// Probes for the tracers

SEC("kprobe/fsnotify_remove_first_event")
int BPF_KPROBE(ig_fa_pick_e, struct fsnotify_group *group)
{
	u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	if (tracer_pid && tracer_pid != tgid)
		return 0;

	if (tracer_group && tracer_group != (u64)group)
		return 0;

	// context for kretprobe
	bpf_map_update_elem(&fsnotify_remove_first_event_ctx, &pid_tgid, &group,
			    0);

	return 0;
}

static __always_inline void
prepare_ee_for_fa_perm(struct enriched_event *ee, struct fsnotify_event *event,
		       struct gadget_event *gadget_event)
{
	u64 pid_tgid;
	struct fanotify_event *fae;
	struct fanotify_perm_event *fpe;
	short unsigned int state;
	__u32 fa_type;

	if (inotify_only)
		return;

	pid_tgid = bpf_get_current_pid_tgid();

	if (ee->type != fanotify)
		return;

	fae = container_of(event, struct fanotify_event, fse);
	fa_type = BPF_CORE_READ_BITFIELD_PROBED(fae, type);
	if (fa_type != FANOTIFY_EVENT_TYPE_PATH_PERM)
		return;

	fpe = container_of(fae, struct fanotify_perm_event, fae);

	ee->tracer_pid = gadget_event->tracer_pid;
	ee->tracer_tid = gadget_event->tracer_tid;
	__builtin_memcpy(ee->tracer_comm, gadget_event->tracer_comm,
			 TASK_COMM_LEN);
	ee->mntns_id = gadget_event->mntns_id;
}

SEC("kretprobe/fsnotify_remove_first_event")
int BPF_KRETPROBE(ig_fa_pick_x, struct fsnotify_event *event)
{
	u64 pid_tgid;
	struct fsnotify_group **group;
	struct enriched_event *ee;
	struct gadget_event *gadget_event;

	// pid_tgid is the task owning the fsnotify fd
	pid_tgid = bpf_get_current_pid_tgid();

	group = bpf_map_lookup_elem(&fsnotify_remove_first_event_ctx,
				    &pid_tgid);
	if (!group)
		return 0;

	gadget_event = gadget_reserve_buf(&events, sizeof(*gadget_event));
	if (!gadget_event)
		goto end;

	/* gadget_event data */
	gadget_event->timestamp = bpf_ktime_get_boot_ns();
	gadget_event->mntns_id = gadget_get_mntns_id();
	gadget_event->tracer_pid = pid_tgid >> 32;
	gadget_event->tracer_tid = (u32)pid_tgid;
	bpf_get_current_comm(&gadget_event->tracer_comm,
			     sizeof(gadget_event->tracer_comm));

	ee = bpf_map_lookup_elem(&enriched_fsnotify_events, &event);
	if (ee) {
		gadget_event->type = ee->type;

		gadget_event->tracee_pid = ee->tracee_pid;
		gadget_event->tracee_tid = ee->tracee_tid;
		__builtin_memcpy(gadget_event->tracee_comm, ee->tracee_comm,
				 TASK_COMM_LEN);
		gadget_event->tracee_mntns_id = ee->tracee_mntns_id;

		gadget_event->prio = ee->prio;

		gadget_event->fa_type = ee->fa_type;
		gadget_event->fa_mask = ee->fa_mask;
		gadget_event->fa_pid = ee->fa_pid;
		gadget_event->fa_flags = ee->fa_flags;
		gadget_event->fa_f_flags = ee->fa_f_flags;

		gadget_event->i_wd = ee->i_wd;
		gadget_event->i_mask = ee->i_mask;
		gadget_event->i_cookie = ee->i_cookie;
		gadget_event->i_ino = ee->i_ino;
		gadget_event->i_ino_dir = ee->i_ino_dir;

		bpf_probe_read_kernel_str(gadget_event->name, PATH_MAX,
					  ee->name);

		prepare_ee_for_fa_perm(ee, event, gadget_event);
	} else {
		if (inotify_only || fanotify_only) {
			gadget_discard_buf(gadget_event);
			goto end;
		}
	}

	/* emit gadget_event */
	gadget_submit_buf(ctx, &events, gadget_event, sizeof(*gadget_event));

end:
	bpf_map_delete_elem(&fsnotify_remove_first_event_ctx, &pid_tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
