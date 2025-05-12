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
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

func NewDockerContainer(name, cmd string, options ...Option) Container {
	c := &DockerContainer{
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

type DockerContainer struct {
	containerSpec

	client *client.Client
}

func (d *DockerContainer) initClient() error {
	var err error
	d.client, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating a client: %w", err)
	}
	return nil
}

func (d *DockerContainer) Run(t *testing.T) {
	if err := d.initClient(); err != nil {
		t.Fatalf("Failed to initialize client: %s", err)
	}

	_ = d.client.ContainerRemove(d.options.ctx, d.name, container.RemoveOptions{})

	reader, err := d.client.ImagePull(d.options.ctx, d.options.image, image.PullOptions{})
	if err != nil {
		t.Fatalf("Failed to pull image container: %s", err)
	}
	io.Copy(io.Discard, reader)

	hostConfig := &container.HostConfig{}
	if d.options.seccompProfile != "" {
		hostConfig.SecurityOpt = []string{fmt.Sprintf("seccomp=%s", d.options.seccompProfile)}
	}
	if d.options.privileged {
		hostConfig.Privileged = true
	}

	if d.options.portBindings != nil {
		hostConfig.PortBindings = d.options.portBindings
	}

	for _, m := range d.options.mounts {
		paths := strings.SplitN(m, ":", 2)
		source := m
		target := m
		if len(paths) == 2 {
			source = paths[0]
			target = paths[1]
		}
		hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: source,
			Target: target,
		})
	}

	resp, err := d.client.ContainerCreate(d.options.ctx, &container.Config{
		Image:      d.options.image,
		Entrypoint: []string{"/bin/sh", "-c", d.cmd},
		Tty:        false,
	}, hostConfig, nil, nil, d.name)
	if err != nil {
		t.Fatalf("Failed to create container: %s", err)
	}
	err = d.client.ContainerStart(d.options.ctx, resp.ID, container.StartOptions{})
	if d.options.expectStartError {
		if err == nil {
			t.Fatalf("Expected error creating container")
		}
		t.Logf("Failed to create container as expected: %s", err)
		if d.options.removal {
			err := d.removeAndClose()
			if err != nil {
				t.Logf("Failed to remove container: %s", err)
			}
		}
		return
	}
	if err != nil {
		t.Fatalf("Failed to start container: %s", err)
	}

	d.id = resp.ID

	if d.options.wait {
		statusCh, errCh := d.client.ContainerWait(d.options.ctx, resp.ID, container.WaitConditionNotRunning)
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Failed to wait for container: %s", err)
			}
		case <-statusCh:
		}
	}
	containerJSON, err := d.client.ContainerInspect(d.options.ctx, d.id)
	if err != nil {
		t.Fatalf("Failed to inspect container: %s", err)
	}
	d.pid = containerJSON.State.Pid

	if len(containerJSON.NetworkSettings.Networks) > 1 {
		t.Fatal("Multiple networks are not supported")
	}

	if len(containerJSON.NetworkSettings.Networks) == 1 {
		d.ip = containerJSON.NetworkSettings.IPAddress
	}

	d.portBindings = containerJSON.NetworkSettings.Ports

	if d.options.logs {
		out, err := d.client.ContainerLogs(d.options.ctx, resp.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
		if err != nil {
			t.Fatalf("Failed to get container logs: %s", err)
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(out)
		t.Logf("Container %q output:\n%s", d.name, buf.String())
	}

	if d.options.removal {
		err := d.removeAndClose()
		if err != nil {
			t.Fatalf("Failed to remove container: %s", err)
		}
	}
}

func (d *DockerContainer) Start(t *testing.T) {
	if d.started {
		t.Logf("Warn(%s): trying to start already running container\n", d.name)
		return
	}
	d.start(t)
	d.started = true
}

func (d *DockerContainer) start(t *testing.T) {
	for _, o := range []Option{WithoutWait(), withoutRemoval()} {
		o(d.options)
	}
	d.Run(t)
}

func (d *DockerContainer) Stop(t *testing.T) {
	if !d.started && !d.options.forceDelete {
		t.Logf("Warn(%s): trying to stop already stopped container\n", d.name)
		return
	}
	if d.client == nil {
		if d.options.forceDelete {
			t.Logf("Warn(%s): trying to stop container with nil client. Forcing deletion\n", d.name)
			if err := d.initClient(); err != nil {
				t.Fatalf("Failed to initialize client: %s", err)
			}
		} else {
			t.Fatalf("Client is not initialized")
		}
	}

	if err := d.removeAndClose(); err != nil {
		t.Fatalf("Failed to stop container: %s", err)
	}
	d.started = false
}

func (d *DockerContainer) removeAndClose() error {
	err := d.client.ContainerRemove(d.options.ctx, d.name, container.RemoveOptions{Force: true})
	if err != nil {
		return fmt.Errorf("removing container: %w", err)
	}

	err = d.client.Close()
	if err != nil {
		return fmt.Errorf("closing client: %w", err)
	}

	return nil
}

func RunDockerFailedContainer(ctx context.Context, t *testing.T) {
	NewDockerContainer("test-ig-failed-container", "/none", WithoutLogs(), WithoutWait(), WithContext(ctx)).Run(t)
}
