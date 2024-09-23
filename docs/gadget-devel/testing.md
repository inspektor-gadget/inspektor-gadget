---
title: 'Testing a Gadget'
sidebar_position: 710
description: 'Testing a Gadget'
---

:::warning

This document is slighty outdated, please check the [existing
gadgets](https://github.com/inspektor-gadget/inspektor-gadget/tree/%IG_BRANCH%/gadgets)
to learn how they implement the tests.

:::

Inspektor Gadget provides a set of helpers to implement tests for your gadget. This document is a small guide showing how to implement tests for the [hello-world gadget](./hello-world-gadget.md).

First, create the testing file, `mygadget_test.go` and import some packages, like:

```go
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

```go
type mygadgetEvent struct {
  eventtypes.Event

  MntNsID   uint64 `json:"mntns_id"`
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

:::warning

TODO: Update this document with:
- Use new normalize functions
- Support other container runtimes than docker

:::

```go
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
          e.MntNsID = 0
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
