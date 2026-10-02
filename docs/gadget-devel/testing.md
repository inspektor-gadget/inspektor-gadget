---
title: 'Testing a Gadget'
sidebar_position: 710
description: 'Testing a Gadget'
---

:::warning

This document is slightly outdated, please check the [existing
gadgets](https://github.com/inspektor-gadget/inspektor-gadget/tree/%IG_BRANCH%/gadgets)
to learn how they implement the tests.

:::

Inspektor Gadget provides a set of helpers to implement tests for your gadget. This document is a small guide showing how to implement tests for the [hello-world gadget](./hello-world-gadget.mdx).

## Gadget images in CI

Pull request jobs build the gadgets once and export the complete gadget set,
including the CI-only gadgets, into a single `gadgets.tar` OCI archive. The
`gadget-images` GitHub Actions artifact shares this archive with the test jobs;
PR gadget images are not pushed to a public registry.

The gadget unit, kernel, and local integration jobs use the archive to populate
a job-local registry and local image store before running tests. To export or
import images locally:

```bash
make -C gadgets export GADGET_ARCHIVE=/tmp/gadgets.tar
sudo ig image import /tmp/gadgets.tar
```

The export target uses the same `GADGETS`, `GADGET_REPOSITORY`, and `GADGET_TAG`
settings as the build. It only exports existing images and does not rebuild them.

For Kubernetes gadget tests, the PR job starts a GitHub Actions registry service
with port 5000 published on the runner. The `setup-minikube` composite action
resolves `host.minikube.internal` from the selected minikube node and uses the
resulting IPv4 address for both publishing and pulling. This avoids hostname
resolution differences between the runner and pods and does not require the
minikube registry addon.

The test jobs use the `prepare-gadget-images` composite action to import the
archive, publish the gadgets to a registry service, generate an ephemeral Cosign
key pair, and sign the published images. The action verifies each signature and
returns the registry endpoint and public key to the tests. This does not require
repository secrets, so it also works for pull requests from forks.

The daemon is configured to allow the registry endpoint through an
`operator.oci.insecure-registries` list and trust the ephemeral public key
through `operator.oci.public-keys` in a `--daemon-config` YAML file. The
multi-tenancy test reuses this file for redeployment and cleanup. Non-PR jobs
continue to publish to GHCR and verify images using the release signing key when
signing is enabled.

The gadget-container and ig container images use the same official GitHub
artifact actions but remain separate, per-platform Docker archives, not part of
`gadgets.tar`. The minikube action can also load the gadget-container archive on
the nodes for integration and Helm tests without requiring a public registry.
Standalone container-listing tests do not need the gadget archive.

The shared `minikube.mk` provides `minikube-host-ip` and `minikube-image-load`
targets. These use the pinned minikube binary and accept `MINIKUBE_PROFILE` to select a
cluster, or use the current profile when it is unset. For example:

```bash
make minikube-host-ip MINIKUBE_PROFILE=minikube-cri-o
```

Image artifacts are retained for one day. Rerunning test jobs after the artifacts
expire requires rerunning the image build jobs as well.

## Writing a gadget test

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
