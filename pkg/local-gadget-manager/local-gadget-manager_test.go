// Copyright 2021 The Inspektor Gadget authors
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

package localgadgetmanager

import (
	"context"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

var rootTest = flag.Bool("root-test", false, "enable tests requiring root")

func TestBasic(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	gadgets := localGadgetManager.ListGadgets()
	if len(gadgets) == 0 {
		t.Fatalf("Failed to get any gadgets")
	}
}

func runTestContainer(t *testing.T, name, command string, containerReadyCallback func()) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("Failed to connect to Docker: %s", err)
	}
	ctx := context.Background()

	_ = cli.ContainerRemove(ctx, name, types.ContainerRemoveOptions{})

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "alpine",
		Cmd:   []string{"/bin/sh", "-c", command},
		Tty:   false,
	}, nil, nil, nil, name)
	if err != nil {
		t.Fatalf("Failed to create container: %s", err)
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		t.Fatalf("Failed to start container: %s", err)
	}

	if containerReadyCallback != nil {
		containerReadyCallback()
	}

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Failed to wait for container: %s", err)
		}
	case <-statusCh:
	}

	err = cli.ContainerRemove(ctx, name, types.ContainerRemoveOptions{Force: true})
	if err != nil {
		t.Fatalf("Failed to remove container: %s", err)
	}
}

func TestSeccomp(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	containerName := "test-local-gadget-seccomp001"
	err = localGadgetManager.AddTracer("seccomp", "my-tracer", containerName)
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}

	runTestContainer(t, containerName, "mkdir /foo", func() {
		//err = localGadgetManager.Operation("my-tracer", "generate")
		//if err != nil {
		//	t.Fatalf("Failed to generate: %s", err)
		//}
	})

	ch, err := localGadgetManager.Stream("my-tracer", nil)
	if err != nil {
		t.Fatalf("Failed to get stream: %s", err)
	}
	results := <-ch
	if !strings.Contains(results, "- mkdir") {
		t.Fatalf("Failed to get correct Seccomp Policy: %s", results)
	}
}

func TestCollector(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	fakeContainer := runcfanotify.ContainerEvent{
		ContainerID:  "my-container",
		ContainerPID: uint32(os.Getpid()),
	}
	localGadgetManager.AddContainer(fakeContainer)

	err = localGadgetManager.AddTracer("socket-collector", "my-tracer1", "my-container")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer1", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}

	err = localGadgetManager.AddTracer("process-collector", "my-tracer2", "my-container")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer2", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}
}
