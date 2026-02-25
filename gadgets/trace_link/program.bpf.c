// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

/*
 * This gadget emits both hard link and symlink events into the same stream:
 *
 * - security_path_link(old_dentry, new_dir, new_dentry)
 * - security_path_symlink(dir, dentry, old_name)
 */

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	bool is_symlink;
	char target[GADGET_PATH_MAX];
	char linkpath[GADGET_PATH_MAX];
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(link, events, event);

SEC("kprobe/security_path_link")
int BPF_KPROBE(ig_trace_link, struct dentry *old_dentry,
	       const struct path *new_dir, struct dentry *new_dentry)
{
	if (gadget_should_discard_data_current())
		return 0;

	struct event *event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->is_symlink = false;

	/* Resolve old path: old_dentry + new_dir->mnt (same fs) */
	struct path old_path;
	old_path.dentry = old_dentry;
	old_path.mnt = BPF_CORE_READ(new_dir, mnt);

	char *s = get_path_str(&old_path);
	if (!s || bpf_probe_read_kernel_str(event->target,
					    sizeof(event->target), s) < 0)
		event->target[0] = 0;

	/* Resolve new path: new_dentry + new_dir->mnt */
	struct path new_path;
	new_path.dentry = new_dentry;
	new_path.mnt = BPF_CORE_READ(new_dir, mnt);

	s = get_path_str(&new_path);
	if (!s || bpf_probe_read_kernel_str(event->linkpath,
					    sizeof(event->linkpath), s) < 0)
		event->linkpath[0] = 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

SEC("kprobe/security_path_symlink")
int BPF_KPROBE(ig_trace_symlink, const struct path *dir, struct dentry *dentry,
	       const char *old_name)
{
	if (gadget_should_discard_data_current())
		return 0;

	struct event *event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->is_symlink = true;

	/* linkpath: full path of symlink being created */
	struct path sym_path;
	sym_path.dentry = dentry;
	sym_path.mnt = BPF_CORE_READ(dir, mnt);

	char *s = get_path_str(&sym_path);
	if (!s || bpf_probe_read_kernel_str(event->linkpath,
					    sizeof(event->linkpath), s) < 0)
		event->linkpath[0] = 0;

	/* target: raw symlink target string */
	if (!old_name ||
	    bpf_probe_read_kernel_str(event->target, sizeof(event->target),
				      old_name) < 0)
		event->target[0] = 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
