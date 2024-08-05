---
title: Hello world gadget
sidebar_position: 200
description: Hello world gadget
---

This is a short getting started guide to write your first gadget. This guide will get you familiar
with the key concepts by implementing a simplified version of the "trace open" (opensnoop) tool.

## Starting from a template

If you want to create a new repository for your gadget, you can use the [gadget-template
repository](https://github.com/inspektor-gadget/gadget-template). This is a
[GitHub tempate repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template).

You can also look for examples in gadgets published on Artifact Hub:

[![Artifact Hub: Gadgets](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/gadgets)](https://artifacthub.io/packages/search?repo=gadgets)

## Starting from scratch

If you already have a git repository for your project and want to add a gadget
to it, you can start from scratch. The rest of this guide assumes you will
start from scratch.

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

// Inspektor Gadget buffer
#include <gadget/buffer.h>

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

Then, create a buffer eBPF map to send events to user space:

```c
// events is the name of the buffer map and 1024 * 256 is its size.
GADGET_TRACER_MAP(events, 1024 * 256);
```

This macro will automatically create a ring buffer if the kernel supports it.
Otherwise, a perf array will be created.

And define a tracer by using the `GADGET_TRACER` macro with the following
parameters:

- Tracer's Name: `open`
- Buffer Map Name: `events`
- Event Structure Name: `event`

```c
// Define a tracer
GADGET_TRACER(open, events, event);
```

After that, we need to define a program that is attached to a hook that provides the information we
need, in this case we'll attach to a tracepoint that is called each time the openat() syscall
is executed.

This program collects the information to fill the event (only pid for now), and then calls
`gadget_submit_buf()` helper to send the event to user space.

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	struct event *event;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

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

// Inspektor Gadget buffer
#include <gadget/buffer.h>

// Inspektor Gadget macros
#include <gadget/macros.h>

struct event {
	__u32 pid;
};

// events is the name of the buffer map and 1024 * 256 is its size.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define a tracer
GADGET_TRACER(open, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx)
{
	struct event *event;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

Check [Gadget eBPF API](./gadget-ebpf-api.md) to learn all functions, macros and
types that Inspektor Gadget exposes to the eBPF programs.

## Building the gadget for the first time

We can now compile our gadget. You don't need to have any build tools installed on the
machine, the [`image build`](./building.md) by default uses docker to run a
container with all dependencies to compile the code.

```bash
$ cd mygadget
$ sudo ig image build -t mygadget:latest .
Successfully built ghcr.io/inspektor-gadget/gadget/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628
```

Take into account that it is possible to customize the build process by defining
a `build.yaml` file. Check the [Building a Gadget](./building.md) section for
more details.

## (Optional) Pushing the gadget image to a container registry

You could push the gadget to a remote container registry. If you're using the same machine for
building and running the gadget, this step can be skipped.

```bash
$ sudo ig image tag mygadget:latest ghcr.io/my-org/mygadget:latest
Successfully tagged with ghcr.io/my-org/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628

$ sudo ig image push ghcr.io/my-org/mygadget:latest
Pushing ghcr.io/my-org/mygadget:latest...
Successfully pushed ghcr.io/my-org/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628
```

For the sake of simplicity this guide doesn't cover signing the gadget image, however, we
strongly encourage you to sign them. Please check [signing](./signing.md) to get
more details.

## Running the gadget

We're now all set to run our gadget for the first time.

```bash
$ sudo ig run mygadget:latest --verify-image=false
PID
1113
1113
1113
1113
1113
1113
1113
1113
1113
1113
1113
1113
1113
1113
1113
1219
220121
```

Great, our program already shows the PID! Can we improve it further?

## Adding more information to the gadget

Let's add some more information to our event, like command and file name.

Add the fields in the event structure.

```c
#define NAME_MAX 255

struct event {
	__u32 pid;
	char comm[TASK_COMM_LEN];
	char filename[NAME_MAX];
};
```

Now create the logic to fill those fields in the `enter_openat` program. Insert them after you have
reserved space for your event structure and before you submit the buffer.

```c
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), (const char *)ctx->args[1]);
```

Build and run the gadget again. Now it provides more information.

```bash
$ sudo ig image build -t mygadget:latest .
....
$ sudo ig run mygadget:latest --verify-image=false
PID                      COMM                     FILENAME
11305                    Chrome_ChildIOT          /dev/shm/.org.chromium.…
11305                    ThreadPoolForeg          /home/mvb/.config/Slack…
11305                    Chrome_ChildIOT          /dev/shm/.org.chromium.…
11305                    ThreadPoolForeg          /home/mvb/.config/Slack…
11305                    Chrome_ChildIOT          /dev/shm/.org.chromium.…
1349                     containerd               /var/lib/containerd/io.…
1349                     containerd               /var/lib/containerd/io.…
1349                     containerd               /var/lib/containerd/io.…
```

## Creating a metadata file

The above formatting is not totally great, the pid column is taking a lot of
space while the filename is being trimmed. The [metadata file](./metadata.md)
contains extra information about the gadget, among other things, it can be used
to specify the format to be used.

An initial version of the metadata file can be created by passing `--update-metadata` to the build command:

```bash
$ sudo ig image build . -t mygadget --update-metadata
```

It'll create a `gadget.yaml` file:

```yaml
name: 'TODO: Fill the gadget name'
description: 'TODO: Fill the gadget description'
homepageURL: 'TODO: Fill the gadget homepage URL'
documentationURL: 'TODO: Fill the gadget documentation URL'
sourceURL: 'TODO: Fill the gadget source code URL'
datasources:
  open:
    fields:
      comm:
        annotations:
          description: 'TODO: Fill field description'
      filename:
        annotations:
          description: 'TODO: Fill field description'
      pid:
        annotations:
          description: 'TODO: Fill field description'
```

Let's edit the file to customize the output. We define some templates for well-known fields like
pid, comm, etc.

```yaml
name: mygadget
description: Example gadget
homepageURL: http://mygadget.com
documentationURL: https://mygadget.com/docs
sourceURL: https://github.com/my-org/mygadget/
datasources:
  open:
    fields:
      comm:
        annotations:
          description: Name of the process opening a file
          template: comm
      filename:
        annotations:
           description: Path of the file being opened
           columns.width: 64
      pid:
        annotations:
          description: PID of the process opening a file
          template: pid
```

Now we can build and run the gadget again

```bash
$ sudo ig image build . -t mygadget
...

$ sudo ig run mygadget:latest --verify-image=false
              PID COMM              FILENAME
             1094 systemd-oomd      /sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/memor…
             1094 systemd-oomd      /sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/memor…
             1094 systemd-oomd      /sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/memor…
             1094 systemd-oomd      /sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/memor…
             1094 systemd-oomd      /sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/memor…
             1094 systemd-oomd      /sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/memor…
             1094 systemd-oomd      /proc/meminfo
            20100 tmux: server      /proc/118135/cmdline
             1094 systemd-oomd      /proc/meminfo
             1094 systemd-oomd      /proc/meminfo
             5803 FSBroker114558    /proc/114558/statm
             5803 FSBroker114558    /proc/114558/statm
             5803 FSBroker114558    /proc/114558/smaps
            20100 tmux: server      /proc/118135/cmdline
             1094 systemd-oomd      /proc/meminfo
           118137 ig                /proc
```

Now the output is much better.

## Filtering and container enrichement

The gadget we created provides information about all events happening on the host, however it (a)
doesn't provide any information about the container generating the event nor (b) allows it to filter
events by a given container.

Inspektor Gadget provides the logic to filter and enrich events with container information.
The first step is to include these two addional header files:

```c
// Inspektor Gadget filtering
#include <gadget/mntns_filter.h>

// Inspektor Gadget types
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
	struct event *event;
	u64 mntns_id;

	mntns_id = gadget_get_mntns_id();
```

Finally, we need to discard the events we're not interested in:

```c
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->mntns_id = mntns_id;
	...
```

The `gadget_should_discard_mntns_id` function is provided to determine if a given event should be
traced or not. This function should be called as early as possible in the program to avoid unnecessary work.

After adding the `gadget_mntns_id` field to the event structure, compiling and running again,
Inspektor Gadget will automatically add the container name column to the output:

```bash
$ sudo ig run mygadget:latest --verify-image=false
RUNTIME.CONTAINERNAME        PID             COMM            FILENAME                        MNTNS_ID
```

However, the output is empty. It's because now the gadget is filtering only events generated by containers.
Create a container and run some commands there:

```bash
$ docker run --rm -ti --name=mycontainer busybox cat /dev/null
```

Only events generated in containers are now printed, and they include the name of the container
generating them.

```bash
$ sudo ig run mygadget:latest --verify-image=false
RUNTIME.CONTAINERNAME MNTNS_ID            PID COMM        FILENAME
mycontainer           4026536181       119341 runc:[2:IN… /proc/self/fd
mycontainer           4026536181       119341 sh          /etc/ld.so.cache
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v…
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v…
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/tls/x86_64/x86_64/lib…
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/tls/x86_64/libm.so.6
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/tls/x86_64/libm.so.6
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/tls/libm.so.6
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/x86_64/x86_64/libm.so…
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/x86_64/libm.so.6
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/x86_64/libm.so.6
mycontainer           4026536181       119341 sh          /lib/x86_64-linux-gnu/libm.so.6
mycontainer           4026536181       119341 sh          /usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-…
mycontainer           4026536181       119341 sh          /usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-
...
```

Additionally, after adding the `gadget_mntns_id` field to the event structure, Inspektor Gadget will
automatically add the flag `--containername`/`-c` to the gadget. This flag allows filtering
events by container name.

The following command doesn't show any event as there is no container with the specified name:

```bash
$ sudo ig run mygadget:latest -c non_existing_container --verify-image=false
RUNTIME.CONTAINERNAME MNTNS_ID            PID COMM        FILENAME
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
	event->uid = (__u32)uid_gid;
	event->gid = (__u32)(uid_gid >> 32);
```

Let's build the gadget with the `--update-metadata` file, so our new fields are automatically added
to the metadata file. Notice the -v option is used to get debugging messages.

```bash
$ sudo ig image build . -t mygadget --update-metadata -v
...
DEBU[0000] Metadata file found, updating it
DEBU[0000] Adding field "mntns_id"
DEBU[0000] Field "pid" already exists, skipping
DEBU[0000] Field "comm" already exists, skipping
DEBU[0000] Field "filename" already exists, skipping
DEBU[0000] Adding field "uid"
DEBU[0000] Adding field "gid"
...
```

The uid, gid and mntns_id (added in the [previous
step](#filtering-and-container-enrichement) fields were added to the metadata
file:

```yaml
      gid:
        annotations:
          description: 'TODO: Fill field description'
      mntns_id:
        annotations:
          description: 'TODO: Fill field description'
      pid:
        annotations:
          description: PID of the process opening a file
          template: pid
      uid:
        annotations:
          description: 'TODO: Fill field description'
```

Edit them, build and run the gadget again:

```yaml
      comm:
        annotations:
          description: Name of the process opening a file
          template: comm
      filename:
        annotations:
          description: Path of the file being opened
          columns.width: 64
      gid:
        annotations:
          description: Group ID opening the file
          template: uid
      mntns_id:
        annotations:
          description: Mount namespace inode id
          template: ns
      pid:
        annotations:
          description: PID of the process opening a file
          template: pid
      uid:
        annotations:
          description: User ID opening the file
          template: uid
```

```bash
$ sudo ig image build . -t mygadget --update-metadata -v
...

$ sudo ig run mygadget:latest --verify-image=false
RUNTIME.CONTAINERN…        PID COMM       FILENAME                                       UID       GID
```

Now, the UID and GID columns have the expected format. Notice also that the MNTNS_ID column is
not showed because the template `ns` hides it by default.

### Closing

Congratulations! You've implemented your first gadget. Check out our [documentation](./index.mdx) to get more
information.
