// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	"context"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/snapshots"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// TODO containerd currently only works on k8s.io namespace
	defaultNamespace = "k8s.io"
)

func RunContainerdContainer(ctx context.Context, t *testing.T, command string, options ...Option) {
	opts := defaultContainerOptions()
	for _, o := range options {
		o(opts)
	}

	nsCtx := namespaces.WithNamespace(ctx, defaultNamespace)
	fullImage := getFullImage(opts)

	client, err := containerd.New("/run/containerd/containerd.sock",
		containerd.WithTimeout(3*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to connect to containerd: %s", err)
	}

	// Download and unpack the image
	image, err := client.Pull(nsCtx, fullImage)
	if err != nil {
		t.Fatalf("Failed to pull the image %q: %s", fullImage, err)
	}

	unpacked, err := image.IsUnpacked(nsCtx, "")
	if err != nil {
		t.Fatalf("image.IsUnpacked: %v", err)
	}
	if !unpacked {
		if err := image.Unpack(nsCtx, ""); err != nil {
			t.Fatalf("image.Unpack: %v", err)
		}
	}

	// Create the container
	var specOpts []oci.SpecOpts
	specOpts = append(specOpts, oci.WithDefaultSpec())
	specOpts = append(specOpts, oci.WithDefaultUnixDevices)
	specOpts = append(specOpts, oci.WithImageConfig(image))
	if len(command) != 0 {
		specOpts = append(specOpts, oci.WithProcessArgs("/bin/sh", "-c", command))
	}
	if opts.seccompProfile != "" {
		t.Fatalf("testutils/containerd: seccomp profiles are not supported yet")
	}

	var spec specs.Spec
	container, err := client.NewContainer(nsCtx, opts.name,
		containerd.WithImage(image),
		containerd.WithImageConfigLabels(image),
		containerd.WithAdditionalContainerLabels(image.Labels()),
		containerd.WithSnapshotter(""),
		containerd.WithNewSnapshot(opts.name, image, snapshots.WithLabels(map[string]string{})),
		containerd.WithImageStopSignal(image, "SIGTERM"),
		containerd.WithSpec(&spec, specOpts...),
	)
	if err != nil {
		t.Fatalf("Failed to create container %q: %s", opts.name, err)
	}

	containerIO := cio.NullIO
	output := &strings.Builder{}
	if opts.logs {
		containerIO = cio.NewCreator(cio.WithStreams(nil, output, output))
	}
	// Now create and start the task
	task, err := container.NewTask(nsCtx, containerIO)
	if err != nil {
		container.Delete(nsCtx, containerd.WithSnapshotCleanup)
		t.Fatalf("Failed to create task %q: %s", opts.name, err)
	}

	err = task.Start(nsCtx)
	if err != nil {
		container.Delete(nsCtx, containerd.WithSnapshotCleanup)
		t.Fatalf("Failed to start task %q: %s", opts.name, err)
	}

	if opts.wait {
		exitStatus, err := task.Wait(nsCtx)
		if err != nil {
			t.Fatalf("Failed to wait on task %q: %s", opts.name, err)
		}
		s := <-exitStatus
		if s.ExitCode() != 0 {
			t.Logf("Exitcode for task %q: %d", opts.name, s.ExitCode())
		}
	}

	if opts.logs {
		t.Logf("Container %q output:\n%s", opts.name, output.String())
	}

	if opts.removal {
		task.Kill(nsCtx, syscall.SIGKILL)
		_, err = task.Delete(nsCtx)
		if err != nil {
			t.Fatalf("Failed to delete task %q: %s", opts.name, err)
		}
		err = container.Delete(nsCtx, containerd.WithSnapshotCleanup)
		if err != nil {
			t.Fatalf("Failed to delete container %q: %s", opts.name, err)
		}
	}
}

func RunContainerdFailedContainer(ctx context.Context, t *testing.T) {
	RunContainerdContainer(ctx, t,
		"/none",
		WithName("test-ig-failed-container"),
		WithoutLogs(),
		WithoutWait(),
	)
}

func RemoveContainerdContainer(ctx context.Context, t *testing.T, name string) {
	client, err := containerd.New("/run/containerd/containerd.sock",
		containerd.WithTimeout(3*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to connect to containerd: %s", err)
	}

	nsCtx := namespaces.WithNamespace(ctx, defaultNamespace)
	container, err := client.LoadContainer(nsCtx, name)
	if err != nil {
		t.Fatalf("Failed to get container %q: %s", name, err)
	}

	task, err := container.Task(nsCtx, nil)
	if err != nil {
		t.Fatalf("Failed to get task %q: %s", name, err)
	}

	task.Kill(nsCtx, syscall.SIGKILL)
	_, err = task.Delete(nsCtx)
	if err != nil {
		t.Fatalf("Failed to delete task %q: %s", name, err)
	}
	err = container.Delete(nsCtx, containerd.WithSnapshotCleanup)
	if err != nil {
		t.Fatalf("Failed to delete container %q: %s", name, err)
	}
}

func getFullImage(opts *containerOptions) string {
	if strings.Contains(opts.image, ":") {
		return opts.image
	}
	return opts.image + ":" + opts.imageTag
}
