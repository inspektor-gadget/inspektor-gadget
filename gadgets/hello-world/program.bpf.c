// program.bpf.c

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/user_stack_map.h>
#include <gadget/filesystem.h>

const volatile bool filepath = false;
GADGET_PARAM(filepath);

const volatile bool exepath = false;
GADGET_PARAM(exepath);


/* copy to library later on */

struct gadget_tlv {
	__u16 total_size;
	__u16 index;
	char *data;
};

struct gadget_tlv_header {
	__u16 size;
	char data[0];
} __attribute__((packed));

struct gadget_tlv_field_header {
	__u16 id;
	__u16 size;
};

void gadget_tlv_init(struct gadget_tlv *tlv, __u16 total_size, void *buf)
{
	tlv->total_size = total_size;
	tlv->index = 0;
	tlv->data = buf;
};

enum __GADGET_PUSH_TYPE {
	GADGET_PUSH_TYPE_KERNEL,
	GADGET_PUSH_TYPE_USER,
};

int __gadget_tlv_push_str(struct gadget_tlv *tlv, __u16 id, __u32 max_size, char *data, __u8 type)
{
	const __u32 tlv_header_size = sizeof(struct gadget_tlv_field_header);

	__u32 index_to_write = tlv->index + tlv_header_size;

	if (index_to_write >= (u32)tlv->total_size-max_size) {
		bpf_printk("gadget_tlv_push: not enough space\n");
		return -1;
	}

//	if (index_to_write + max_size >= (u32)tlv->total_size) {
//		bpf_printk("gadget_tlv_push: not enough space\n");
//		return -1;
//	}
//
//	// TODO: this check is needed to avoid a verifier error, no idea why!
	if (index_to_write > max_size) {
		return -1;
	}

	int size;
	switch (type) {
	case GADGET_PUSH_TYPE_KERNEL:
		size = bpf_probe_read_kernel_str(tlv->data + index_to_write, max_size, data);
		break;
	case GADGET_PUSH_TYPE_USER:
		size = bpf_probe_read_user_str(tlv->data + index_to_write, max_size, data);
		break;
	default:
		bpf_printk("gadget_tlv_push: unknown type %d\n", type);
		return -1;
	}
	if (size < 0) {
		bpf_printk("gadget_tlv_push failed: %d\n", size);
		return -1;
	}


	if (size > 1024) {
		bpf_printk("gadget_tlv_push: size %d > max_size %d\n", size, max_size);
		return -1;
	}

	struct gadget_tlv_field_header *header = (struct gadget_tlv_field_header *)&tlv->data[tlv->index];
	header->id = id;
	header->size = (u16)size;

	tlv->index += (u16) size + (u16) tlv_header_size;

	return 0;
}

int gadget_tlv_push_user_str(struct gadget_tlv *tlv, __u16 id, __u32 max_size, char *data)
{
	return __gadget_tlv_push_str(tlv, id, max_size, data, GADGET_PUSH_TYPE_USER);
}

int gadget_tlv_push_kernel_str(struct gadget_tlv *tlv, __u16 id, __u32 max_size, char *data)
{
	return __gadget_tlv_push_str(tlv, id, max_size, data, GADGET_PUSH_TYPE_KERNEL);
}


/* end library code */

#define FILE_NAME_MAX 4096
#define EXEC_PATH_MAX 4096

struct event {
	__u64 foo;
	struct gadget_tlv_header tlv;
} __attribute__((packed));

// events is the name of the buffer map and 1024 * 256 is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	char *filename = (char *)ctx->args[1];
	struct event *event;
	int ret;

	// allocate more than needed to have space for the filename
	// TODO: how to know the size before allocating the event?
	// TODO: This is an issue for ring buffers as the whole buffer is submitted
	int max_event_size = sizeof(*event);

	// TODO: enabling these conditional causes a verifier error
	//if (filepath) {
		max_event_size += FILE_NAME_MAX + sizeof(struct gadget_tlv_field_header);
	//}
	//if (exepath) {
		max_event_size += EXEC_PATH_MAX + sizeof(struct gadget_tlv_field_header);
	//}

	event = gadget_reserve_buf(&events, max_event_size);
	if (!event)
		return 0;

	struct gadget_tlv tlv;
	gadget_tlv_init(&tlv, max_event_size, &event->tlv.data[0]);

	if (filepath) {
		ret = gadget_tlv_push_user_str(&tlv, 1, FILE_NAME_MAX, filename);
		if (ret < 0) {
			gadget_discard_buf(event);
			return 0;
		}
	}

	if (exepath) {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
		char *exepath = get_path_str(&exe_file->f_path);
		ret = gadget_tlv_push_kernel_str(&tlv, 2, EXEC_PATH_MAX, exepath);
		if (ret < 0) {
			gadget_discard_buf(event);
			return 0;
		}
	}

	event->tlv.size = tlv.index;
	bpf_printk("tlv_size is %d", tlv.index);

	gadget_submit_buf(ctx, &events, event, sizeof(*event) + tlv.index);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
