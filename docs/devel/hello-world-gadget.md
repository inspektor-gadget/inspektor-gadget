---
title: Hello world gadget
weight: 100
description: >
  Hello world gadget
---

> ⚠️ This feature is experimental. In order for the commands to work, the `IG_EXPERIMENTAL` env var must be set to `true`
>
> ```bash
> $ export IG_EXPERIMENTAL=true
> ```

This is a short getting started guide to write your first gadget. This guide will get you familiar
with the key concepts by implementing a simplified version of the "trace open" (opensnoop) tool.

The first step is to create an empty folder where the source code of the gadget will be stored:

```bash
$ mkdir myexecsnoop
```

## Implementing the eBPF program

The eBPF code contains the source code for the programs that are injected in the kernel to collect
information. Let's create a file called `program.bpf.c` and put the following contents in there.

The first thing we need is to include some header files.

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
```

- `vmlinux.h`: definition for the different types of the kernel
- `bpf/bpf_helpers.h`: definition for eBPF helpers signatures

Then, we have to specify a event structure with all the information our gadget will provide. Let's
only put the pid for the time being.

```c
struct event {
	__u32 pid;
};

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));
```

Then, create a perf ring buffer eBPF map to send events to user space. The `print_` prefix tells
Inspektor Gadget to poll this map to get the events sent by our gadget.

```c
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__type(value, struct event);
} print_events SEC(".maps");
```

After that, we need to define a program that is attached to a hook that provides the information we
need, this this case we'll attach to a tracepoint that is called each time the openat() syscall
intiates execution.

This program collects the information to fill the event (only pid for now), and then calls
`bpf_perf_event_output` helper to send the event to user space.

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event event = {};

	event.pid = bpf_get_current_pid_tgid() >> 32;

	bpf_perf_event_output(ctx, &print_events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}
```

Finally, it's needed to define the license of the eBPF code.

```c
char LICENSE[] SEC("license") = "GPL";
```

The full file should look like:

```c
// program.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct event {
	__u32 pid;
};

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__type(value, struct event);
} print_events SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event event = {};

	event.pid = bpf_get_current_pid_tgid() >> 32;

	bpf_perf_event_output(ctx, &print_events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

## Creating a definition file

The definition file contains metadata about the gadget, like its name, documentation, and the
information it provides. It's called `definition.yaml` by default:

The first part is very generic, name and description:

```yaml
name: mygadget
description: example gadget
```

The second part includes information about the data the gadget provides. Each field on the event
structure is called a column, and this allows to configure how they are printed. In this case, the
`pid` column uses the `pid` template taht has some predefined formatting in Inspektor Gadget.

```yaml
name: mygadget
description: example gadget
columns:
  - name: pid
    template: pid
    order: 1000
    visible: true
```

The full definition file is

```yaml
# definition.yaml
name: mygadget
description: example gadget
columns:
  - name: pid
    template: pid
    order: 1000
    visible: true
```

## Building the gadget

Now we've created our eBPF and definition files, we're ready to build the gadget. You don't need to
have any dependency on the machine, the `image build` by default uses a container with all
dependencies to compile the code.

```
$ cd mygadget
$ sudo -E ig image build --builder-image=ghcr.io/mauriciovasquezbernal/inspektor-gadget-ebpf-builder:latest -t mygadget:latest .
INFO[0000] Experimental features enabled
Successfully built docker.io/library/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628
```

## (Optional) Pushing the gadget image to a container registry

You could push the gadget to a remote container registry.

```bash
$ sudo -E ig image tag mygadget:latest ghcr.io/mauriciovasquezbernal/mygadget:latest
INFO[0000] Experimental features enabled
Successfully tagged with ghcr.io/mauriciovasquezbernal/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628

$ sudo -E ig image push ghcr.io/mauriciovasquezbernal/mygadget:latest
INFO[0000] Experimental features enabled
Pushing ghcr.io/mauriciovasquezbernal/mygadget:latest...
Successfully pushed ghcr.io/mauriciovasquezbernal/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628
```

## Running the gadget

We're now all set to run our gadget for the first time.

```bash
$ sudo -E ig run mygadget:latest
INFO[0000] Experimental features enabled
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME                                                                        PID
                                                                                             748
                                                                                             748
                                                                                             748
                                                                                             748
                                                                                             748
                                                                                             748
                                                                                             748
                                                                                             748
                                                                                             1
```

The tool shows the PID, however that's not very useful.

## Adding more information to the gadget

Let's add some more information to our event, like command and file name.

Add the fields in the event structure.

```c
#define NAME_MAX 255

struct event {
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 filename[NAME_MAX];
};
```

And create the logic to fill those fiels in the `enter_openat` program.

```c
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), (const char *)ctx->args[1]);
```

Also, add the new columns to the definition file.

```yaml
  - name: comm
    template: comm
    width: 16
    order: 1001
    visible: true
  - name: filename
    min_width: 24
    width: 32
    order: 1006
    visible: true
```

Build and run the gadget again. Now it provides more information.

```
$ sudo -E ig image build --builder-image=ghcr.io/mauriciovasquezbernal/inspektor-gadget-ebpf-builder:latest -t mygadget:latest .

$ sudo -E ig run mygadget:latest
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME                PID     COMM             FILENAME
                                     3657    DNS Res~ver #98  /etc/hosts
                                     3657    Cache2 I/O       /proc/self/mountinfo
                                     3657    Cache2 I/O       /proc/self/mountinfo
                                     3657    Cache2 I/O       /proc/self/mountinfo
                                     3657    Cache2 I/O       /proc/self/mountinfo
```

### Filtering and container enrichement

The gadget we created provides information about all events happenning on the host, however it (a)
doesn't provide any information about the container generating the even nor (b) allows to filter
events by a given container.

Inspektor Gadget provides the logic to filter and enrich events with container information.
This first step is to include these two addional header files

```c
#include <gadget/mntns_filter.h>
#include <gadget/types.h>
```

- `gadget/mntns_filter.h`: Defines an eBPF map and some helper functions used to filter events by containers
- `gadget/types.h`: Defines different Inspektor Gadget specific types, like `mnt_ns_id_t`.


Add the following field to the event structure.

```c
	mnt_ns_id_t mntns_id;
```

And then, on the program, set this field. `gadget_get_mntns_id` is a helper function provided by
Inspektor Gadget to get the current mount namespace.

```c
	event.mntns_id = gadget_get_mntns_id();
```

Finally, we need to discard events we're not interested in:

```c
	if (gadget_should_discard_mntns_id(event.mntns_id))
		return 0;
```

The `gadget_should_discard_mntns_id` function is provided to understand if a given event should be
traced or not, this call should be placed as soon as possible on the program to avoid doing useless
work.

After compiling and running again, this is the result:

```
$ sudo -E ig run mygadget:latest
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME                PID     COMM             FILENAME
```

Nothing is shown because now the gadget is filtering only events generated by containers, create a
container and run some commands there:

```bash
$ docker run --rm -ti --name=mycontainer busybox cat /dev/null
```

Only events generated in containers are now printed, and they include the name of the container
generating them.

```bash
RUNTIME.CONTAINERNAME                PID     COMM             FILENAME
...
mycontainer                          198948  cat              /lib/x86_64/libm.so.6
mycontainer                          198948  cat              /lib/libm.so.6
mycontainer                          198948  cat              /lib/libresolv.so.2
mycontainer                          198948  cat              /lib/libc.so.6
mycontainer                          198948  cat              /dev/null
```

This is also possible to filter by container name now, the following command doesn't show any event as there are not containers with that name.

```bash
$ sudo -E ig run mygadget:latest -c non_existing_container
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME                PID     COMM             FILENAME
```

### Closing

Congratulations! You've implemented your first gadget. Check our documentation to get more information.
