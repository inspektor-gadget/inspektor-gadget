/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2016 Brendan Gregg */
/* Copyright (c) 2022-2023 Rong Tao */
/* Copyright (c) 2025 The Inspektor Gadget authors */

/* Initially based on BCC ttysnoop tool:
 * https://github.com/iovisor/bcc/blob/master/tools/ttysnoop.py
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

#define MAX_BUF_SIZE 8192

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	u32 len;
	char buf[MAX_BUF_SIZE];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(ttysnoop, events, event);

#define READ 0
#define WRITE 1

SEC("kprobe/tty_write")
int BPF_KPROBE(tty_write_e, struct kiocb *iocb, struct iov_iter *from)
{
	struct event *event;

	if (gadget_should_discard_data_current())
		return 0;

	if (BPF_CORE_READ(from, data_source) != WRITE)
		return 0;

	event = gadget_reserve_buf(&events, sizeof(struct event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	if (!bpf_core_field_exists(from->iter_type))
		return 0;

	// enum iter_type does not have ITER_UBUF prior to Linux v6.0:
	// https://github.com/torvalds/linux/commit/fcb14cb1bdacec5b4374fe161e83fb8208164a85
	enum iter_type type = BPF_CORE_READ(from, iter_type);

	if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
	    type == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
		bpf_probe_read_kernel(&event->len, sizeof(event->len),
				      &from->__ubuf_iovec.iov_len);

		u32 len = event->len;
		if (len > MAX_BUF_SIZE) {
			len = MAX_BUF_SIZE;
		}
		bpf_probe_read_user(&event->buf, len,
				    BPF_CORE_READ(from, __ubuf_iovec.iov_base));
	}

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
