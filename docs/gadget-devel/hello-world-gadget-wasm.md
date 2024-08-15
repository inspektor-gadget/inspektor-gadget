---
title: Hello world gadget with Wasm
sidebar_position: 410
description: Hello world gadget with Wasm module
---

This guide explores the wasm support to implement complex logic in our gadget.
This is a continuation of [hello world gadget](./hello-world-gadget.md), be sure
you are familiar with that guide before continuing with this.

### Creating our first wasm program

Create a folder named `go` next to the `program.bpf.c` file. In there
we create a new file named `program.go`. As a first step, let's define the
`init`, `start` and `stop` functions and emit some log messages from them:

```go
package main

import (
	"github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetInit
func gadgetInit() int {
	api.Info("init: hello from wasm")
	return 0
}

//export gadgetStart
func gadgetStart() int {
	api.Info("start: hello from wasm")
	return 0
}

//export gadgetStop
func gadgetStop() int {
	api.Info("stop: hello from wasm")
	return 0
}

// The main function is not used, but it's still required by the compiler
func main() {}
```

Run the following commands in the `go` directory to initialize the Golang module:

```bash
$ cd go
$ go mod init mygadget
go: creating new go.mod: module mygadget
go: to add module requirements and sums:
        go mod tidy
$ go mod tidy
go: finding module for package github.com/inspektor-gadget/inspektor-gadget/wasmapi/go
go: found github.com/inspektor-gadget/inspektor-gadget/wasmapi/go in github.com/inspektor-gadget/inspektor-gadget v0.31.0
```

We also need a `build.yaml` file that indicates the gadget includes a Golang
program that needs to be compiled to a wasm module:

```yaml
wasm: go/program.go
```

Build the gadget

```bash
$ sudo ig image build . -t mygadget:latest
```

and run it:

```bash
$ sudo ig run mygadget:latest --verify-image=false
WARN[0000] image signature verification is disabled due to using corresponding option
INFO[0000] init: hello from wasm
WARN[0000] image signature verification is disabled due to using corresponding option
INFO[0000] init: hello from wasm
RUNTIME.CONTAINERNAME        MNTNS_ID            PID            COMM           FILENAME
INFO[0001] start: hello from wasm
...
^CINFO[0009] stop: hello from wasm
```

You can see how the different messages coming from wasm are printed in the
terminal.

### Manipulating fields

Now let's do something more interesting. Let's suppose we want to redact the
user's name in the path of the file. Manipulating strings in eBPF is usually
complicated, leave aside using regular expressions.

Our goal is to look for strings like `/home/<user-name>/...` and redact (replace
by `***`) the user name part. This can be done by using a regular expression.

Let's add it to the `gadgetInit` function like this:

```go
//export gadgetInit
func gadgetInit() int {
	api.Info("init: hello from wasm")

	// Get the "open" datasource (name used in the GADGET_TRACER macro)
	ds, err := api.GetDataSource("open")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	// Get the field we're interested in
	filenameF, err := ds.GetField("filename")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	pattern := regexp.MustCompile(`^(/home/)(.*?)/(.*)$`)

	// Subscribe to all events from "open" so we manipulate the data in the callback
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		fileName := filenameF.String(data)
		replaced := pattern.ReplaceAllString(fileName, "${1}***/${3}")
		filenameF.SetString(data, replaced)
	}, 0)

	return 0
}
```

Build and run the gadget again:

```bash
$ sudo ig image build . -t mygadget:latest
...


$ sudo ig run mygadget:latest --verify-image=false
WARN[0000] image signature verification is disabled due to using corresponding option
INFO[0000] init: hello from wasm
WARN[0000] image signature verification is disabled due to using corresponding option
INFO[0000] init: hello from wasm
RUNTIME.CONTAINERNAME        MNTNS_ID            PID            COMM           FILENAME
INFO[0001] start: hello from wasm
```

Let's generate some events from a container:

```bash
$ docker run --name c3 --rm -it busybox sh

# inside the container:
$ mkdir /home/mvb
$ touch /home/mvb/xxx.txt
$ cat /home/mvb/xxx.txt
```

The gadget redacts the user name as expected:

```bash
RUNTIME.CONTAINERNAME        MNTNS_ID            PID            COMM           FILENAME
c3                           4026534569          226136         cat            /home/***/xxx.txt
```

### Adding new fields

There are cases where we want to add new fields from wasm. For instance, let's
add a field that contains a human readable representation of the event.

The `gadgetInit` functions now looks like:

```go
//export gadgetInit
func gadgetInit() int {
	api.Info("init: hello from wasm")

	// Get the "open" datasource (name used in the GADGET_TRACER macro)
	ds, err := api.GetDataSource("open")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	// Get the field we're interested in
	filenameF, err := ds.GetField("filename")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	pidF, err := ds.GetField("pid")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	humanF, err := ds.AddField("human", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	pattern := regexp.MustCompile(`^(/home/)(.*?)/(.*)$`)

	// Subscribe to all events from "open" so we manipulate the data in the callback
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		fileName := filenameF.String(data)
		replaced := pattern.ReplaceAllString(fileName, "${1}***/${3}")
		filenameF.SetString(data, replaced)

		human := fmt.Sprintf("file %q was opened by %d", fileName, pidF.Uint32(data))
		humanF.SetString(data, human)
	}, 0)

	return 0
}
```

Build and run the gadget again. This time using `-o json` to easily see the
output from it:

```bash
$ sudo ig image build . -t mygadget:latest
...

$ sudo ig run mygadget:latest --verify-image=false -o jsonpretty
{
  "comm": "cat",
  "filename": "/home/***/xxx.txt",
  "human": "file '/home/mvb/xxx.txt' was opened by 121351",
  "k8s": {
    "container": "",
    "hostnetwork": false,
    "namespace": "",
    "node": "",
    "pod": ""
  },
  "mntns_id": 4026534661,
  "pid": 121351,
  "runtime": {
    "containerId": "2de33de4d1c73be918916322bf488a32f8b7a6eea0903422278fa13766e36f8f",
    "containerImageDigest": "",
    "containerImageName": "busybox",
    "containerName": "c3",
    "runtimeName": "docker"
  }
}
```

Notice how the human field is there when `cat /home/mvb/xxx.txt` is executed in
the container.

### Dropping events

TBD!
