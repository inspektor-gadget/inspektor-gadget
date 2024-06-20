---
title: Hello world gadget
weight: 110
description: >
  Hello world gadget
---

> [!WARNING]
> This feature is experimental. To activate the commands, you must set the `IG_EXPERIMENTAL` environment variable to `true`.
>
> ```bash
> $ export IG_EXPERIMENTAL=true
> ```

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

Optionally, you can employ the `GADGET_TRACER` macro to define a tracer with the
following parameters:

- Tracer's Name: `open`
- Buffer Map Name: `events`
- Event Structure Name: `event`

This information enables Inspektor Gadget to generate the metadata file automatically.
Refer to the [metadata file](#creating-a-metadata-file) section for detailed instructions.

```c
// [Optional] Define a tracer
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

// [Optional] Define a tracer
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

## Building the gadget for the first time

We can now compile our gadget. You don't need to have any dependency on the machine, the `image
build` by default uses docker to run a container with all dependencies to compile the code.

```bash
$ cd mygadget
$ sudo -E ig image build -t mygadget:latest .
INFO[0000] Experimental features enabled
Successfully built ghcr.io/inspektor-gadget/gadget/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628
```

Take into account that it is possible to customize the build process by defining a `build.yaml` file.
Check the [Customizing your build](../../docs/core-concepts/images.md#customizing-your-build)
section for more details.

## (Optional) Pushing the gadget image to a container registry

You could push the gadget to a remote container registry. If you're using the same machine for
building and running the gadget, this step can be skipped.

```bash
$ sudo -E ig image tag mygadget:latest ghcr.io/my-org/mygadget:latest
INFO[0000] Experimental features enabled
Successfully tagged with ghcr.io/my-org/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628

$ sudo -E ig image push ghcr.io/my-org/mygadget:latest
INFO[0000] Experimental features enabled
Pushing ghcr.io/my-org/mygadget:latest...
Successfully pushed ghcr.io/my-org/mygadget:latest@sha256:dd3f5c357983bb863ef86942e36f4c851933eec4b32ba65ee375acb1c514f628
```

## Signing the gadget image

Once you have pushed your gadget image to a container registry, it's highly recommended to sign it for security reasons.
Tools like [cosign](https://docs.sigstore.dev/signing/signing_with_containers/) can be used for this purpose.
Signed images ensure integrity and authenticity, adding an extra layer of trust.
By default, Inspektor Gadget forbids running unsigned gadget images, but you can skip the verification using the `--verify-image=false` flag at your own risks.

For more details on the verification process, refer to the [verification documentation](../getting-started/verify.md#verify-image-based-gadgets).

## Running the gadget

We're now all set to run our gadget for the first time.

```bash
$ sudo -E ig run mygadget:latest --verify-image=false
INFO[0000] Experimental features enabled
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
$ sudo -E ig image build -t mygadget:latest .
....
$ sudo -E ig run mygadget:latest --verify-image=false
INFO[0000] Experimental features enabled
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

The above formatting is not totally great, the pid column is taking a lot of space while the
filename is being trimmed. The metadata file contains extra information about the gadget, among
other things, it can be used to specify the format to be used.

An initial version of the metadata file can be created by passing `--update-metadata` to the build command:

> [!NOTE]
> The `tracers` and `structs` sections will only be generated if the eBPF program defined a tracer
> using the `GADGET_TRACER` macro.

```bash
$ sudo -E ig image build . -t mygadget --update-metadata
```

It'll create a `gadget.yaml` file:

```yaml
name: 'TODO: Fill the gadget name'
description: 'TODO: Fill the gadget description'
homepageURL: 'TODO: Fill the gadget homepage URL'
documentationURL: 'TODO: Fill the gadget documentation URL'
sourceURL: 'TODO: Fill the gadget source code URL'
tracers:
  open:
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
homepageURL: http://mygadget.com
documentationURL: https://mygadget.com/docs
sourceURL: https://github.com/my-org/mygadget/
tracers:
  open:
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

$ sudo -E ig run mygadget:latest --verify-image=false
INFO[0000] Experimental features enabled
PID             COMM            FILENAME
224707          git             .git/objects/cd/4968fd25e0b4d597f93993a29a9821c1a263d6
224707          git             .git/objects/57/d7fb78a6f22dbfcf66d3175d06ce49d0e0dff5
224707          git             .git/objects/03/5159622b915b7f55f64b6c0a30536531d08c5f
19463           CompositorTileW /dev/shm/.org.chromium.Chromium.5pbSUV
19463           CompositorTileW /dev/shm/.org.chromium.Chromium.96jgiV
19463           CompositorTileW /dev/shm/.org.chromium.Chromium.3tqlBS
224708          Sandbox Forked  /proc/self/uid_map
224708          Sandbox Forked  /proc/self/setgroups
224708          Sandbox Forked  /proc/self/gid_map
3830            firefox-bin     /proc/224708/oom_score_adj
224708          Sandbox Forked
224710          Chroot Helper
224708          firefox-bin     /usr/lib/firefox/tls/x86_64/x86_64/libmozsandbox.so
224708          firefox-bin     /usr/lib/firefox/tls/x86_64/libmozsandbox.so
224708          firefox-bin     /usr/lib/firefox/tls/x86_64/libmozsandbox.so
224708          firefox-bin     /usr/lib/firefox/tls/libmozsandbox.so
224708          firefox-bin     /usr/lib/firefox/x86_64/x86_64/libmozsandbox.so
224708          firefox-bin     /usr/lib/firefox/x86_64/libmozsandbox.so
224708          firefox-bin     /usr/lib/firefox/x86_64/libmozsandbox.so
224708          firefox-bin     /usr/lib/firefox/libmozsandbox.so
```

Now the output is much better.

### Filtering and container enrichement

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
	if (gadget_should_discard_mntns_id(mntns_id)) {
		return 0;
	}

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
$ sudo -E ig run mygadget:latest --verify-image=false
INFO[0000] Experimental features enabled
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
RUNTIME.CONTAINERNAME        PID             COMM            FILENAME                        MNTNS_ID
mycontainer                  225805          cat             /lib/tls/libm.so.6              4026532256
mycontainer                  225805          cat             /lib/x86_64/x86_64/libm.so.6    4026532256
mycontainer                  225805          cat             /lib/x86_64/libm.so.6           4026532256
mycontainer                  225805          cat             /lib/x86_64/libm.so.6           4026532256
mycontainer                  225805          cat             /lib/libm.so.6                  4026532256
mycontainer                  225805          cat             /lib/libresolv.so.2             4026532256
mycontainer                  225805          cat             /lib/libc.so.6                  4026532256
mycontainer                  225805          cat             /dev/null                       4026532256
```

Additionally, after adding the `gadget_mntns_id` field to the event structure, Inspektor Gadget will
automatically add the flag `--containername`/`-c` to the gadget. This flag allows filtering
events by container name.

The following command doesn't show any event as there is no container with the specified name:

```bash
$ sudo -E ig run mygadget:latest -c non_existing_container --verify-image=false
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME        PID             COMM            FILENAME                        MNTNS_ID
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
$ sudo -E ig image build . -t mygadget --update-metadata -v
INFO[0000] Experimental features enabled
...
DEBU[0001] Metadata file found, updating it
DEBU[0001] Tracer "open" already defined, skipping
DEBU[0001] Field "pid" already exists, skipping
DEBU[0001] Field "comm" already exists, skipping
DEBU[0001] Adding field "uid"
DEBU[0001] Adding field "gid"
DEBU[0001] Field "filename" already exists, skipping
DEBU[0001] Adding field "mntns_id"
...
```

The uid, gid and mntns_id (added in the [previous
step](#filtering-and-container-enrichement) fields were added to the metadata
file:

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
    - name: mntns_id
      description: 'TODO: Fill field description'
      attributes:
        width: 20
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
    - name: mntns_id
      description: Mount namespace inode id
      attributes:
        template: ns
```

```bash
$ sudo -E ig image build . -t mygadget --update-metadata -v
...

$ sudo -E ig run mygadget:latest --verify-image=false
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME  PID          COMM         FILENAME                                        UID         GID
```

Now, the UID and GID columns have the expected format. Notice also that the MNTNS_ID column is
not showed because the template `ns` hides it by default.

## Adding tests for the gadget

In order to ensure the gadget works as expected, you can create a corresponding test file.
To do so, you need to call it `mygadget_test.go` and import some packages, like:

```golang
package main

import (
  "testing"

  "github.com/stretchr/testify/require"

  // helper functions for creating and running commands in a container.
  "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"

  igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"

  // wrapper function for ig binary
  igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"

  // helper functions for parsing and comparing output.
  "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"

  // Event struct for fields enriched by ig.
  eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)
```

Then, we create a structure with all the information the gadget provides.

```golang
type mygadgetEvent struct {
  eventtypes.Event

  MountNsID uint64 `json:"mountnsid"`
  Pid       uint32 `json:"pid"`
  Uid       uint32 `json:"uid"`
  Gid       uint32 `json:"gid"`
  Comm      string `json:"comm"`
  Filename  string `json:"filename"`
}
```

Later we create a test function called `TestMyGadget()`.
In this, we first create a container manager (can be either `docker` or `containerd`). After that, we create a command to run the gadget with various options.
Finally, these commands are used as arguments in `RunTestSteps()`:

```golang
func TestMyGadget(t *testing.T) {
  cn := "test-mygadget"

  // returns a container manager which implements an interface with methods for creating new container
  // and running commands within that container.
  containerFactory, err := containers.NewContainerFactory("docker")
  require.NoError(t, err, "new container factory")

  mygadgetCmd := igrunner.New(
    // gadget repository and tag can be added with the following environment variables:
    // - $GADGET_REPOSITORY
    // - $GADGET_TAG
    "mygadget",
    igrunner.WithFlags("--runtimes=docker", "--timeout=5"),
    igrunner.WithValidateOutput(
      func(t *testing.T, output string) {
        expectedEntry := &mygadgetEvent{
          Event: eventtypes.Event{
            CommonData: eventtypes.CommonData{
              Runtime: eventtypes.BasicRuntimeMetadata{
                RuntimeName:   eventtypes.String2RuntimeName("docker"),
                ContainerName: cn,
              },
            },
          },
          Comm:     "cat",
          Filename: "/dev/null",
          Uid:      1000,
          Gid:      1111,
        }

        // used to "normalize" the output, sets random value fields to a default value
        // so that it only includes non-default values for the fields we can verify.
        normalize := func(e *mygadgetEvent) {
          e.MountNsID = 0
          e.Pid = 0

          e.Runtime.ContainerID = ""
          e.Runtime.ContainerImageName = ""
          e.Runtime.ContainerImageDigest = ""
        }

        // parses the output and matches it to expectedEntry.
        match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
      },
    ),
  )

  testSteps := []igtesting.TestStep{
    // WithStartAndStop used to start the container command, then, wait for other commands to run
    // and stop later and verify the output.
    containerFactory.NewContainer(cn, "while true; do setuidgid 1000:1111 cat /dev/null; sleep 0.1; done", containers.WithStartAndStop()),
    mygadgetCmd,
  }

  igtesting.RunTestSteps(testSteps, t)
}
```

(Optional) If running the test for a gadget whose image resides in a remote container registry, you can define environment variables for the gadget repository and tag.

```bash
$ export GADGET_REPOSITORY=ghcr.io/my-org GADGET_TAG=latest
```

We are all set now to run the test.

```bash
$ go test -exec 'sudo -E' -v ./mygadget_test.go
```

### Closing

Congratulations! You've implemented your first gadget. Check out our documentation to get more
information.
