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
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
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
	d.client, err = client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("creating a client: %w", err)
	}
	return nil
}

func (d *DockerContainer) Run(t *testing.T) {
	err := d.initClient()
	require.NoError(t, err, "Failed to initialize client")

	_, _ = d.client.ContainerRemove(d.options.ctx, d.name, client.ContainerRemoveOptions{})

	reader, err := d.client.ImagePull(d.options.ctx, d.options.image, client.ImagePullOptions{})
	require.NoError(t, err, "Failed to pull image container")
	io.Copy(io.Discard, reader)

	hostConfig := &container.HostConfig{}
	if d.options.seccompProfile != "" {
		hostConfig.SecurityOpt = []string{fmt.Sprintf("seccomp=%s", d.options.seccompProfile)}
	}
	if d.options.privileged {
		hostConfig.Privileged = true
	}
	if d.options.sysctls != nil {
		hostConfig.Sysctls = d.options.sysctls
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

	resp, err := d.client.ContainerCreate(d.options.ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image:      d.options.image,
			Entrypoint: []string{"/bin/sh", "-c", d.cmd},
			Tty:        false,
		},
		HostConfig: hostConfig,
		Name:       d.name,
	})
	require.NoError(t, err, "Failed to create container")
	_, err = d.client.ContainerStart(d.options.ctx, resp.ID, client.ContainerStartOptions{})
	if d.options.expectStartError {
		require.Error(t, err, "Expected error creating container")
		t.Logf("Failed to create container as expected: %s", err)
		if d.options.removal {
			err := d.removeAndClose()
			if err != nil {
				t.Logf("Failed to remove container: %s", err)
			}
		}
		return
	}
	require.NoError(t, err, "Failed to start container")

	d.id = resp.ID

	if d.options.wait {
		waitResult := d.client.ContainerWait(d.options.ctx, resp.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
		select {
		case err := <-waitResult.Error:
			require.NoError(t, err, "Failed to wait for container")
		case <-waitResult.Result:
		}
	}
	result, err := d.client.ContainerInspect(d.options.ctx, d.id, client.ContainerInspectOptions{})
	require.NoError(t, err, "Failed to inspect container")
	containerJSON := result.Container
	d.pid = containerJSON.State.Pid

	require.LessOrEqual(t, len(containerJSON.NetworkSettings.Networks), 1, "Multiple networks are not supported")

	if len(containerJSON.NetworkSettings.Networks) == 1 {
		for _, nw := range containerJSON.NetworkSettings.Networks {
			d.ip = nw.IPAddress.String()
		}
	}

	d.portBindings = containerJSON.NetworkSettings.Ports

	if d.options.logs {
		logResult, err := d.client.ContainerLogs(d.options.ctx, resp.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
		require.NoError(t, err, "Failed to get container logs")
		buf := new(bytes.Buffer)
		buf.ReadFrom(logResult)
		t.Logf("Container %q output:\n%s", d.name, buf.String())
	}

	if d.options.removal {
		err := d.removeAndClose()
		require.NoError(t, err, "Failed to remove container")
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
			err := d.initClient()
			require.NoError(t, err, "Failed to initialize client")
		} else {
			require.Fail(t, "Client is not initialized")
		}
	}

	if !d.options.expectStartError {
		killAndWait := func(signal string, wait time.Duration, next func()) {
			_, err := d.client.ContainerKill(d.options.ctx, d.id, client.ContainerKillOptions{Signal: signal})
			require.NoError(t, err, "killing container with %s", signal)
			ctxTimeout, cancel := context.WithTimeout(d.options.ctx, wait)
			defer cancel()
			waitResult := d.client.ContainerWait(ctxTimeout, d.id, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
			select {
			case err := <-waitResult.Error:
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) && next != nil {
						next()
						return
					}
					require.NoError(t, err, "Failed to wait for container")
				}
			case <-waitResult.Result:
			}
		}

		killAndWait("SIGINT", 5*time.Second, func() {
			killAndWait("SIGKILL", 2*time.Second, nil)
		})

		if d.options.expectedExitCode != nil {
			// check exit code
			result, err := d.client.ContainerInspect(d.options.ctx, d.id, client.ContainerInspectOptions{})
			require.NoError(t, err, "inspecting container")

			require.Equal(t, *d.options.expectedExitCode, result.Container.State.ExitCode)
		}
	}

	err := d.removeAndClose()
	require.NoError(t, err, "Failed to stop container")
	d.started = false
}

func (d *DockerContainer) removeAndClose() error {
	_, err := d.client.ContainerRemove(d.options.ctx, d.name, client.ContainerRemoveOptions{Force: true})
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
