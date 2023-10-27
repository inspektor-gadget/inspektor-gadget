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
$ mkdir mygadget
```

## Implementing the eBPF program

The eBPF code contains the source code for the programs that are injected in the kernel to collect
information. Let's create a file called `program.bpf.c` and put the following contents in there.

The first thing we need is to include some header files.

```c
// Kernel types definitions
// Check https://blog.aquasec.com/vmlinux.h-ebpf-programs for more details
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>

// Inspektor Gadget macros
#include <gadget/macros.h>
```

Then, we have to specify a structure with all the information our gadget will provide. Let's only
put the pid for the time being.

```c
struct event {
	__u32 pid;
};
```

Then, create a perf event array eBPF map to send events to user space:

```c
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");
```

And mark this map as a tracer map, i.e. a map that is used to push events to user space:

```c
// open is the name for the tracer
// events is the name of the perf event array map
// event is the structure type
GADGET_TRACER(open, events, event);
```

After that, we need to define a program that is attached to a hook that provides the information we
need, in this case we'll attach to a tracepoint that is called each time the openat() syscall
is executed.

This program collects the information to fill the event (only pid for now), and then calls
`bpf_perf_event_output` helper to send the event to user space.

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event event = {};

	event.pid = bpf_get_current_pid_tgid() >> 32;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
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

// Kernel types definitions
// Check https://blog.aquasec.com/vmlinux.h-ebpf-programs for more details
#include <vmlinux.h>

// eBPF helpers signatures
// Check https://man7.org/linux/man-pages/man7/bpf-helpers.7.html to learn
// more about different available helpers
#include <bpf/bpf_helpers.h>

// Inspektor Gadget macros
#include <gadget/macros.h>

struct event {
	__u32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// open is the name of the tracer
// events is the name of the perf event array map
// event is the structure type
GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event event = {};

	event.pid = bpf_get_current_pid_tgid() >> 32;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

## Building the gadget for the first time

We can now compile our gadget. You don't need to have any dependency on the machine, the `image
build` by default uses docker to run a container with all dependencies to compile the code.

```bash
$ cd mygadget
$ sudo -E ig image build -t mygadget:latest .
INFO[0000] Experimental features enabled
Successfully built docker.io/library/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628
```

## (Optional) Pushing the gadget image to a container registry

You could push the gadget to a remote container registry. If you're using the same machine for
building and running the gadget, this step can be skipped.

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
PID
40342
40342
40342
40342
40342
40342
40342
40342
40342
40342
40342
40342
40342
1485789
1485789
50077
40342
```

Great, our program already shows the PID! Can we improve it further?

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

Now create the logic to fill those fields in the `enter_openat` program.

```c
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), (const char *)ctx->args[1]);
```

Build and run the gadget again. Now it provides more information.

```bash
$ sudo -E ig image build -t mygadget:latest .
....
$ sudo -E ig run mygadget:latest
INFO[0000] Experimental features enabled
PID                           COMM                                          FILENAME
45205                         cri-dockerd                                   /var/lib/cri-dockerd/sandbox
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/cont…
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/cont…
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/meta…
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/cont…
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/cont…
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/meta…
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/cont…
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/cont…
45019                         dockerd                                       /var/lib/docker/image/overlay2/imagedb/meta…
```

## Creating a metadata file

The above formatting is not totally great, the pid column is taking a lot of space while the
filename is being trimmed. The metadata file contains extra information about the gadget, among
other things, it can be used to specify the format to be used.

An initial version of the metadata file can be created by passing `--update-metadata` to the build command:

```bash
$ sudo -E ig image build . -t mygadget --update-metadata
```

It'll create a `gadget.yaml` file:

```yaml
name: 'TODO: Fill the gadget name'
description: 'TODO: Fill the gadget description'
tracers:
  events:
    mapName: events
    structName: event
structs:
  event:
    fields:
    - name: pid
      description: 'TODO: Fill field description'
      attributes:
        width: 16
        alignment: left
        ellipsis: end
    - name: comm
      description: 'TODO: Fill field description'
      attributes:
        width: 16
        alignment: left
        ellipsis: end
    - name: filename
      description: 'TODO: Fill field description'
      attributes:
        width: 16
        alignment: left
        ellipsis: end
```

Let's edit the file to customize the output. We define some templates for well-known fields like
pid, comm, etc.

```yaml
name: mygadget
description: Example gadget
tracers:
  events:
    mapName: events
    structName: event
structs:
  event:
    fields:
    - name: pid
      description: PID of the process opening a file
      attributes:
        template: pid
    - name: comm
      description: Name of the process opening a file
      attributes:
        template: comm
    - name: filename
      description: Path of the file being opened
      attributes:
        width: 64
        alignment: left
        ellipsis: end
```

Now we can build and run the gadget again

```bash
$ sudo -E ig image build . -t mygadget
...

$ sudo -E ig run mygadget:latest
INFO[0000] Experimental features enabled
PID                   COMM             FILENAME
46614                 kubelet          /sys/fs/cgroup/rdma/kubepods/besteffort/podc2911a0a-7a13-4567-9f1d-4591610b6e87
46614                 kubelet          /sys/fs/cgroup/unified/kubepods/besteffort/pod98e07b21-af7e-469d-ad7e-2191105f29…
46614                 kubelet          /sys/fs/cgroup/unified/kubepods/burstable/podfe9f0773b92e204b518f2edde7abe987
46614                 kubelet          /sys/fs/cgroup/rdma/kubepods/besteffort/pod3bfa187d-29cf-43a4-bb0a-8ca482da6fa4
46614                 kubelet          /sys/fs/cgroup/rdma/kubepods/besteffort/pod3bfa187d-29cf-43a4-bb0a-8ca482da6fa4/…
46614                 kubelet          /sys/fs/cgroup/rdma/kubepods/besteffort/pod34776137-2fd7-44e0-885c-5eebd7b0525a
46614                 kubelet          /sys/fs/cgroup/rdma/kubepods/besteffort/pod34776137-2fd7-44e0-885c-5eebd7b0525a/…
46614                 kubelet          /sys/fs/cgroup/rdma/kubepods/besteffort/pod653943e5-5eae-417f-8d41-d6771eb32424
46614                 kubelet          /sys/fs/cgroup/rdma/kubepods/besteffort/pod653943e5-5eae-417f-8d41-d6771eb32424/…
46614                 kubelet          /sys/fs/cgroup/unified/kubepods/besteffort/pod653943e5-5eae-417f-8d41-d6771eb324…
```

Now the output is much better.


### Filtering and container enrichement

The gadget we created provides information about all events happening on the host, however it (a)
doesn't provide any information about the container generating the event nor (b) allows it to filter
events by a given container.

Inspektor Gadget provides the logic to filter and enrich events with container information.
The first step is to include these two addional header files:

```c
#include <gadget/mntns_filter.h>
#include <gadget/types.h>
```

- `gadget/mntns_filter.h`: Defines an eBPF map and some helper functions used to filter events by containers
- `gadget/types.h`: Inspektor Gadget specific types, like `gadget_mntns_id`.


Add the following field to the event structure.

```c
struct event {
	...
	gadget_mntns_id mntns_id;
	...
}
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

The `gadget_should_discard_mntns_id` function is provided to determine if a given event should be
traced or not, this call should be placed as soon as possible on the program to avoid doing useless
work.

After compiling and running again, this is the result:

```bash
$ sudo -E ig run mygadget:latest
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME        PID             COMM            FILENAME
```

Nothing is shown because now the gadget is filtering only events generated by containers, create a
container and run some commands there:

```bash
$ docker run --rm -ti --name=mycontainer busybox cat /dev/null
```

Only events generated in containers are now printed, and they include the name of the container
generating them.

```bash
RUNTIME.CONTAINERNAME        PID             COMM            FILENAME
...
mycontainer                  225805          cat             /lib/tls/libm.so.6
mycontainer                  225805          cat             /lib/x86_64/x86_64/libm.so.6
mycontainer                  225805          cat             /lib/x86_64/libm.so.6
mycontainer                  225805          cat             /lib/x86_64/libm.so.6
mycontainer                  225805          cat             /lib/libm.so.6
mycontainer                  225805          cat             /lib/libresolv.so.2
mycontainer                  225805          cat             /lib/libc.so.6
mycontainer                  225805          cat             /dev/null
```

It's now possible to filter by container name. The following command doesn't show any event as there
is no container with the specified name.

```bash
$ sudo -E ig run mygadget:latest -c non_existing_container
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME        PID             COMM            FILENAME
```

## Updating the gadget

Some times we have to update our gadgets, like adding more fields to the generated event for instance.
Let's add the following fields to the event struct:

```c
struct event {
	...
	__u32 uid;
	__u32 gid;
	...
}
```

and add the logic in the eBPF program to fill them:

```c
	__u64 uid_gid = bpf_get_current_uid_gid();
	event.uid = (__u32)uid_gid;
	event.gid = (__u32)(uid_gid >> 32);
```

Let's build the gadget with the `--update-metadata` file, so our new fields are automatically added
to the metadata file. Notice the -v option is used to get debugging messages.

```bash
$ sudo -E ig image build . -t mygadget --update-metadata -v
INFO[0000] Experimental features enabled
DEBU[0000] Metadata file found, updating it
DEBU[0000] Tracer using map "events" already defined, skipping
DEBU[0000] Adding column "uid"
DEBU[0000] Adding column "gid"
DEBU[0000] Column "pid" already exists, skipping
DEBU[0000] Column "comm" already exists, skipping
DEBU[0000] Column "filename" already exists, skipping
Successfully built docker.io/library/mygadget:latest@sha256:faa54348214b5dbbedea866cf3b683e77df07c799deb43ab2a1443fa436c6828
```

The uid and gid fields were added to the metadata file:

```yaml
    - name: uid
      description: 'TODO: Fill field description'
      attributes:
        width: 16
        alignment: left
        ellipsis: end
    - name: gid
      description: 'TODO: Fill field description'
      attributes:
        width: 16
        alignment: left
        ellipsis: end
```

Edit them, build and run the gadget again:

```yaml
    - name: uid
      description: User ID opening the file
      attributes:
        template: uid
    - name: gid
      description: Group ID opening the file
      attributes:
        template: uid
```

```bash
$ sudo -E ig image build . -t mygadget --update-metadata -v
...

$ sudo -E ig run mygadget:latest
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME  PID          COMM         FILENAME                                        UID         GID
```

Now the UID and GID fields are also printed.

### Closing

Congratulations! You've implemented your first gadget. Check out our documentation to get more
information.
