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
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/cri/constants"
	"github.com/containerd/containerd/snapshots"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	taskKillTimeout = 3 * time.Second
)

func NewContainerdContainer(name, cmd string, options ...Option) Container {
	c := &ContainerdContainer{
		containerSpec: containerSpec{
			name:    name,
			cmd:     cmd,
			options: defaultContainerOptions(),
		},
	}
	for _, o := range options {
		o(c.options)
	}
	return c
}

type ContainerdContainer struct {
	containerSpec

	client     *containerd.Client
	nsCtx      context.Context
	exitStatus <-chan containerd.ExitStatus
}

func (c *ContainerdContainer) initClientAndCtx() error {
	var err error
	c.client, err = containerd.New("/run/containerd/containerd.sock",
		containerd.WithTimeout(3*time.Second),
	)
	if err != nil {
		return fmt.Errorf("creating a client: %w", err)
	}

	namespace := constants.K8sContainerdNamespace
	if c.options.namespace != "" {
		namespace = c.options.namespace
	}
	c.nsCtx = namespaces.WithNamespace(c.options.ctx, namespace)
	return nil
}

func (c *ContainerdContainer) Run(t *testing.T) {
	if err := c.initClientAndCtx(); err != nil {
		t.Fatalf("Failed to initialize client: %s", err)
	}

	// Download and unpack the image
	fullImage := getFullImage(c.options)
	image, err := c.client.Pull(c.nsCtx, fullImage)
	if err != nil {
		t.Fatalf("Failed to pull the image %q: %s", fullImage, err)
	}

	unpacked, err := image.IsUnpacked(c.nsCtx, "")
	if err != nil {
		t.Fatalf("image.IsUnpacked: %v", err)
	}
	if !unpacked {
		if err := image.Unpack(c.nsCtx, ""); err != nil {
			t.Fatalf("image.Unpack: %v", err)
		}
	}

	// Create the container
	var specOpts []oci.SpecOpts
	specOpts = append(specOpts, oci.WithDefaultSpec())
	specOpts = append(specOpts, oci.WithDefaultUnixDevices)
	specOpts = append(specOpts, oci.WithImageConfig(image))
	if len(c.cmd) != 0 {
		specOpts = append(specOpts, oci.WithProcessArgs("/bin/sh", "-c", c.cmd))
	}
	if c.options.seccompProfile != "" {
		t.Fatalf("testutils/containerd: seccomp profiles are not supported yet")
	}
	if c.options.portBindings != nil {
		t.Fatalf("testutils/containerd: Port bindings are not supported yet")
	}

	var spec specs.Spec
	container, err := c.client.NewContainer(c.nsCtx, c.name,
		containerd.WithImage(image),
		containerd.WithImageConfigLabels(image),
		containerd.WithAdditionalContainerLabels(image.Labels()),
		containerd.WithSnapshotter(""),
		containerd.WithNewSnapshot(c.name, image, snapshots.WithLabels(map[string]string{})),
		containerd.WithImageStopSignal(image, "SIGTERM"),
		containerd.WithSpec(&spec, specOpts...),
	)
	if err != nil {
		t.Fatalf("Failed to create container %q: %s", c.name, err)
	}
	c.id = container.ID()

	containerIO := cio.NullIO
	output := &strings.Builder{}
	if c.options.logs {
		containerIO = cio.NewCreator(cio.WithStreams(nil, output, output))
	}
	// Now create and start the task
	task, err := container.NewTask(c.nsCtx, containerIO)
	if err != nil {
		container.Delete(c.nsCtx, containerd.WithSnapshotCleanup)
		t.Fatalf("Failed to create task %q: %s", c.name, err)
	}

	err = task.Start(c.nsCtx)
	if err != nil {
		container.Delete(c.nsCtx, containerd.WithSnapshotCleanup)
		t.Fatalf("Failed to start task %q: %s", c.name, err)
	}

	c.exitStatus, err = task.Wait(c.nsCtx)
	if err != nil {
		t.Fatalf("Failed to wait on task %q: %s", c.name, err)
	}
	c.pid = int(task.Pid())

	if c.options.wait {
		s := <-c.exitStatus
		if s.ExitCode() != 0 {
			t.Logf("Exitcode for task %q: %d", c.name, s.ExitCode())
		}
	}

	if c.options.logs {
		t.Logf("Container %q output:\n%s", c.name, output.String())
	}

	if c.options.removal {
		err := c.deleteAndClose(t, task, container)
		if err != nil {
			t.Fatalf("Failed to delete container %q: %s", c.name, err)
		}
	}
}

func (c *ContainerdContainer) Start(t *testing.T) {
	if c.started {
		t.Logf("Warn(%s): trying to start already running container\n", c.name)
		return
	}
	c.start(t)
	c.started = true
}

func (c *ContainerdContainer) start(t *testing.T) {
	for _, o := range []Option{WithoutWait(), withoutRemoval()} {
		o(c.options)
	}
	c.Run(t)
}

func (c *ContainerdContainer) Stop(t *testing.T) {
	if !c.started && !c.options.forceDelete {
		t.Logf("Warn(%s): trying to stop already stopped container\n", c.name)
		return
	}
	if c.client == nil {
		if c.options.forceDelete {
			t.Logf("Warn(%s): trying to stop container with nil client. Forcing deletion\n", c.name)
			if err := c.initClientAndCtx(); err != nil {
				t.Fatalf("Failed to initialize client: %s", err)
			}
		} else {
			t.Fatalf("Client is not initialized")
		}
	}

	c.stop(t)
	c.started = false
}

// deleteAndClose kill the task, delete the container and close the client
func (c *ContainerdContainer) deleteAndClose(t *testing.T, task containerd.Task, container containerd.Container) error {
	task.Kill(c.nsCtx, syscall.SIGKILL)

	// We need to wait until the task is killed before trying to delete it. But
	// don't wait forever as the task might be already stopped.
	select {
	case <-c.exitStatus:
	case <-time.After(taskKillTimeout):
		t.Logf("Timeout %v waiting for container's task %q to be killed. Go ahead with deletion",
			taskKillTimeout, c.name)
	}

	_, err := task.Delete(c.nsCtx)
	if err != nil {
		return fmt.Errorf("deleting task %q: %w", c.name, err)
	}

	err = container.Delete(c.nsCtx, containerd.WithSnapshotCleanup)
	if err != nil {
		return fmt.Errorf("deleting container %q: %w", c.name, err)
	}

	err = c.client.Close()
	if err != nil {
		return fmt.Errorf("closing client: %w", err)
	}

	return nil
}

func (c *ContainerdContainer) stop(t *testing.T) {
	container, err := c.client.LoadContainer(c.nsCtx, c.name)
	if err != nil {
		t.Fatalf("Failed to get container %q: %s", c.name, err)
	}

	task, err := container.Task(c.nsCtx, nil)
	if err != nil {
		t.Fatalf("Failed to get task %q: %s", c.name, err)
	}

	err = c.deleteAndClose(t, task, container)
	if err != nil {
		t.Fatalf("Failed to delete container %q: %s", c.name, err)
	}
}

func getFullImage(options *containerOptions) string {
	if strings.Contains(options.image, ":") || strings.Contains(options.image, "@") {
		return options.image
	}
	return options.image + ":" + options.imageTag
}

func RunContainerdFailedContainer(ctx context.Context, t *testing.T) {
	NewContainerdContainer("test-ig-failed-container", "/none", WithoutLogs(), WithoutWait(), WithContext(ctx)).Run(t)
}
