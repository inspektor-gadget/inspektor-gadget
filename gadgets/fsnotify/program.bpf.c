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
#include <gadget/core_fixes.bpf.h>

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
	interrupted = 0x03, // tracee interrupted (state != FAN_EVENT_ANSWERED)
	// FAN_AUDIT and FAN_INFO not handled
};

struct process {
	__u32 ppid;
	__u32 pid;
	__u32 tid;
	char comm[TASK_COMM_LEN];
	char pcomm[TASK_COMM_LEN];
};

enum i_mask_set : u32 {
	IN_ACCESS = 0x00000001,
	IN_MODIFY = 0x00000002,
	IN_ATTRIB = 0x00000004,
	IN_CLOSE_WRITE = 0x00000008,
	IN_CLOSE_NOWRITE = 0x00000010,
	IN_OPEN = 0x00000020,
	IN_MOVED_FROM = 0x00000040,
	IN_MOVED_TO = 0x00000080,
	IN_CREATE = 0x00000100,
	IN_DELETE = 0x00000200,
	IN_DELETE_SELF = 0x00000400,
	IN_MOVE_SELF = 0x00000800,
	IN_UNMOUNT = 0x00002000,
	IN_Q_OVERFLOW = 0x00004000,
	IN_IGNORED = 0x00008000,
	IN_CLOSE = (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE),
	IN_MOVE = (IN_MOVED_FROM | IN_MOVED_TO),
	IN_ONLYDIR = 0x01000000,
	IN_DONT_FOLLOW = 0x02000000,
	IN_EXCL_UNLINK = 0x04000000,
	IN_MASK_CREATE = 0x10000000,
	IN_MASK_ADD = 0x20000000,
	IN_ISDIR = 0x40000000,
	IN_ONESHOT = 0x80000000,

};

enum fa_mask_set : u32 {
	FAN_ACCESS = 0x00000001,
	FAN_MODIFY = 0x00000002,
	FAN_ATTRIB = 0x00000004,
	FAN_CLOSE_WRITE = 0x00000008,
	FAN_CLOSE_NOWRITE = 0x00000010,
	FAN_OPEN = 0x00000020,
	FAN_MOVED_FROM = 0x00000040,
	FAN_MOVED_TO = 0x00000080,
	FAN_CREATE = 0x00000100,
	FAN_DELETE = 0x00000200,
	FAN_DELETE_SELF = 0x00000400,
	FAN_MOVE_SELF = 0x00000800,
	FAN_OPEN_EXEC = 0x00001000,
	FAN_Q_OVERFLOW = 0x00004000,
	FAN_FS_ERROR = 0x00008000,
	FAN_OPEN_PERM = 0x00010000,
	FAN_ACCESS_PERM = 0x00020000,
	FAN_OPEN_EXEC_PERM = 0x00040000,
	FAN_EVENT_ON_CHILD = 0x08000000,
	FAN_RENAME = 0x10000000,
	FAN_ONDIR = 0x40000000,
};

struct enriched_event {
	enum type type;

	struct process tracee;
	struct process tracer;

	// mntns_id cannot yet be part of struct process because Inspektor Gadget
	// only support one mntns_id per event.
	gadget_mntns_id tracee_mntns_id;
	__u64 tracer_mntns_id;

	// uids and gids cannot yet be part of struct process because the
	// UidGidResolver does not yet support those fields in an inner struct
	gadget_uid tracee_uid_raw;
	gadget_gid tracee_gid_raw;
	gadget_uid tracer_uid_raw;
	gadget_gid tracer_gid_raw;

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
	gadget_timestamp timestamp_raw;

	enum type type_raw;

	struct process tracee;
	struct process tracer;

	// mntns_id cannot yet be part of struct process because Inspektor Gadget
	// only support one mntns_id per event.
	gadget_mntns_id tracee_mntns_id;
	__u64 tracer_mntns_id;

	// uids and gids cannot yet be part of struct process because the
	// UidGidResolver does not yet support those fields in an inner struct
	gadget_uid tracee_uid_raw;
	gadget_gid tracee_gid_raw;
	gadget_uid tracer_uid_raw;
	gadget_gid tracer_gid_raw;

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
	enum fa_mask_set fa_mask_raw;
	enum i_mask_set i_mask_raw;

	enum fanotify_event_type fa_type_raw;
	__u32 fa_pid;
	__u32 fa_flags;
	__u32 fa_f_flags;
	enum fa_response fa_response_raw;

	__s32 i_wd;
	__u32 i_cookie;
	__u32 i_ino;
	__u32 i_ino_dir;

	char name[PATH_MAX];
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(fsnotify, events, gadget_event);

static __always_inline void process_init(struct process *p, __u64 pid_tgid,
					 struct task_struct *task)
{
	struct task_struct *parent;
	p->pid = pid_tgid >> 32;
	p->tid = (u32)pid_tgid;
	bpf_get_current_comm(&p->comm, sizeof(p->comm));
	parent = BPF_CORE_READ(task, real_parent);
	if (parent != NULL) {
		p->ppid = (pid_t)BPF_CORE_READ(parent, tgid);
		bpf_probe_read_kernel(&p->pcomm, sizeof(p->pcomm),
				      parent->comm);
	}
}

// Linux < v6.10
struct fsnotify_group___with_prio_int {
	unsigned int priority;
};

// Linux >= 6.10
// https://github.com/torvalds/linux/commit/477cf917dd02853ba78a73cdeb6548889e5f8cd7
enum fsnotify_group_prio___new {
	FSNOTIFY_PRIO_NORMAL = 0, /* normal notifiers, no permissions */
	FSNOTIFY_PRIO_CONTENT, /* fanotify permission events */
	FSNOTIFY_PRIO_PRE_CONTENT, /* fanotify pre-content events */
	__FSNOTIFY_PRIO_NUM
};
struct fsnotify_group___with_prio_enum {
	enum fsnotify_group_prio___new priority;
};

static __always_inline __u32 get_priority(struct fsnotify_group *group)
{
	if (bpf_core_type_matches(struct fsnotify_group___with_prio_int)) {
		struct fsnotify_group___with_prio_int *g =
			(struct fsnotify_group___with_prio_int *)group;
		return BPF_CORE_READ(g, priority);
	}
	if (bpf_core_type_matches(struct fsnotify_group___with_prio_enum)) {
		struct fsnotify_group___with_prio_enum *g =
			(struct fsnotify_group___with_prio_enum *)group;
		return BPF_CORE_READ(g, priority);
	}
	bpf_core_unreachable();
	return 0;
}

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
	struct task_struct *task;
	u64 pid_tgid;
	u64 uid_gid;
	struct enriched_event *ee;
	struct fsnotify_insert_event_value *value;
	struct fanotify_event *fae;
	struct inotify_event_info *ine;
	int name_len;
	struct path *p = NULL;

	task = (struct task_struct *)bpf_get_current_task();
	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();

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

	// fsnotify_insert_event() might not add the event, but
	// fsnotify_destroy_event() will be called in any cases.
	// So it is safe to add an entry in the map even if fsnotify_insert_event
	// does not insert an event.

	bpf_map_update_elem(&enriched_fsnotify_events, &event,
			    &empty_enriched_event, BPF_NOEXIST);
	ee = bpf_map_lookup_elem(&enriched_fsnotify_events, &event);
	if (!ee)
		return 0;

	process_init(&ee->tracee, pid_tgid, task);
	ee->tracee_mntns_id = gadget_get_current_mntns_id();
	ee->tracee_uid_raw = (u32)uid_gid;
	ee->tracee_gid_raw = (u32)(uid_gid >> 32);

	ee->prio = get_priority(group);

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
			// Nothing to do
			break;
		}
	}

	return 0;
}

SEC("kprobe/fsnotify_destroy_event")
int BPF_KPROBE(fsnotify_destroy_event, struct fsnotify_group *group,
	       struct fsnotify_event *event)
{
	struct task_struct *task;
	u64 pid_tgid;
	u64 uid_gid;
	struct fsnotify_insert_event_value *value;
	struct fanotify_event *fae;
	struct fanotify_perm_event *fpe;
	short unsigned int state;
	__u32 fa_type;
	__u32 fa_mask;
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

	task = (struct task_struct *)bpf_get_current_task();
	uid_gid = bpf_get_current_uid_gid();

	gadget_event->type_raw = fa_resp;
	gadget_event->fa_type_raw = fa_type;
	gadget_event->prio = get_priority(group);

	gadget_event->timestamp_raw = bpf_ktime_get_boot_ns();

	ee = bpf_map_lookup_elem(&enriched_fsnotify_events, &event);
	if (ee) {
		gadget_event->tracer_mntns_id = ee->tracer_mntns_id;
		gadget_event->tracer = ee->tracer;
	}

	process_init(&gadget_event->tracee, pid_tgid, task);
	gadget_event->tracee_mntns_id = gadget_get_current_mntns_id();
	gadget_event->tracee_uid_raw = (u32)uid_gid;
	gadget_event->tracee_gid_raw = (u32)(uid_gid >> 32);

	bpf_probe_read_kernel_str(gadget_event->name, PATH_MAX,
				  get_path_str(&fpe->path));

	fa_mask = BPF_CORE_READ(fae, mask);
	gadget_event->fa_mask_raw = (enum fa_mask_set)fa_mask;
	gadget_event->fa_pid = BPF_CORE_READ(fae, pid, numbers[0].nr);
	gadget_event->fa_flags = BPF_CORE_READ(group, fanotify_data.flags);
	gadget_event->fa_f_flags = BPF_CORE_READ(group, fanotify_data.f_flags);

	state = BPF_CORE_READ(fpe, state);
	if (state == FAN_EVENT_ANSWERED) {
		gadget_event->fa_response_raw = BPF_CORE_READ(fpe, response);
		gadget_event->fa_response_raw &= allow | deny;
	} else {
		gadget_event->fa_response_raw = interrupted;
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
	struct fanotify_event *fae;
	__u32 fa_type;

	if (inotify_only)
		return;

	if (ee->type != fanotify)
		return;

	fae = container_of(event, struct fanotify_event, fse);
	fa_type = BPF_CORE_READ_BITFIELD_PROBED(fae, type);
	if (fa_type != FANOTIFY_EVENT_TYPE_PATH_PERM)
		return;

	ee->tracer = gadget_event->tracer;
	ee->tracer_mntns_id = gadget_event->tracer_mntns_id;
}

SEC("kretprobe/fsnotify_remove_first_event")
int BPF_KRETPROBE(ig_fa_pick_x, struct fsnotify_event *event)
{
	struct task_struct *task;
	u64 pid_tgid;
	u64 uid_gid;
	struct fsnotify_group **group;
	struct enriched_event *ee;
	struct gadget_event *gadget_event;

	// pid_tgid is the task owning the fsnotify fd
	task = (struct task_struct *)bpf_get_current_task();
	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();

	group = bpf_map_lookup_elem(&fsnotify_remove_first_event_ctx,
				    &pid_tgid);
	if (!group)
		return 0;

	gadget_event = gadget_reserve_buf(&events, sizeof(*gadget_event));
	if (!gadget_event)
		goto end;

	/* gadget_event data */
	gadget_event->timestamp_raw = bpf_ktime_get_boot_ns();

	process_init(&gadget_event->tracer, pid_tgid, task);
	gadget_event->tracer_mntns_id = gadget_get_current_mntns_id();
	gadget_event->tracer_uid_raw = (u32)uid_gid;
	gadget_event->tracer_gid_raw = (u32)(uid_gid >> 32);

	ee = bpf_map_lookup_elem(&enriched_fsnotify_events, &event);
	if (ee) {
		gadget_event->type_raw = ee->type;

		gadget_event->tracee = ee->tracee;
		gadget_event->tracee_mntns_id = ee->tracee_mntns_id;

		gadget_event->prio = ee->prio;

		gadget_event->fa_type_raw = ee->fa_type;
		gadget_event->fa_mask_raw = (enum fa_mask_set)ee->fa_mask;
		gadget_event->fa_pid = ee->fa_pid;
		gadget_event->fa_flags = ee->fa_flags;
		gadget_event->fa_f_flags = ee->fa_f_flags;

		gadget_event->i_wd = ee->i_wd;
		gadget_event->i_mask_raw = (enum i_mask_set)ee->i_mask;
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
