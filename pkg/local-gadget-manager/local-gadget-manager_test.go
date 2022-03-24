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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	dnstypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
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

func runTestContainer(t *testing.T, name, image, command, seccompProfile string) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("Failed to connect to Docker: %s", err)
	}
	ctx := context.Background()

	_ = cli.ContainerRemove(ctx, name, types.ContainerRemoveOptions{})

	reader, err := cli.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		t.Fatalf("Failed to pull image container: %s", err)
	}
	io.Copy(ioutil.Discard, reader)

	hostConfig := &container.HostConfig{}
	if seccompProfile != "" {
		hostConfig.SecurityOpt = []string{fmt.Sprintf("seccomp=%s", seccompProfile)}
	}

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: image,
		Cmd:   []string{"/bin/sh", "-c", command},
		Tty:   false,
	}, hostConfig, nil, nil, name)
	if err != nil {
		t.Fatalf("Failed to create container: %s", err)
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		t.Fatalf("Failed to start container: %s", err)
	}

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Failed to wait for container: %s", err)
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		t.Fatalf("Failed to get container logs: %s", err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(out)
	t.Logf("Container %s output:\n%s", image, string(buf.Bytes()))

	err = cli.ContainerRemove(ctx, name, types.ContainerRemoveOptions{Force: true})
	if err != nil {
		t.Fatalf("Failed to remove container: %s", err)
	}

	err = cli.Close()
	if err != nil {
		t.Fatalf("Failed to close docker client: %s", err)
	}
}

func stacks() string {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

func currentFdList(t *testing.T) (ret string) {
	files, err := ioutil.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("Failed to list fds: %s", err)
	}
	for _, file := range files {
		fd, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}
		dest, err := os.Readlink("/proc/self/fd/" + file.Name())
		if err != nil {
			continue
		}
		ret += fmt.Sprintf("%d: %s\n", fd, dest)
	}
	return
}

func checkFdList(t *testing.T, initialFdList string, attempts int, sleep time.Duration) {
	for i := 0; ; i++ {
		finalFdList := currentFdList(t)
		if initialFdList == finalFdList {
			return
		}

		if i >= (attempts - 1) {
			t.Fatalf("After %d attempts, fd leaked:\n%s\n%s", attempts, initialFdList, finalFdList)
		}

		time.Sleep(sleep)
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

	initialFdList := currentFdList(t)

	containerName := "test-local-gadget-seccomp001"
	err = localGadgetManager.AddTracer("seccomp", "my-tracer", containerName, "Stream")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}

	runTestContainer(t, containerName, "docker.io/library/alpine", "mkdir /foo ; echo OK", "")

	ch, err := localGadgetManager.Stream("my-tracer", nil)
	if err != nil {
		t.Fatalf("Failed to get stream: %s", err)
	}
	results := <-ch
	if !strings.Contains(results, "- mkdir") {
		t.Fatalf("Failed to get correct Seccomp Policy: %s", results)
	}

	err = localGadgetManager.Delete("my-tracer")
	if err != nil {
		t.Fatalf("Failed to delete tracer: %s", err)
	}

	s := stacks()
	keyword := "seccomp"
	if strings.Contains(s, keyword) {
		t.Fatalf("Error: stack contains %q:\n%s", keyword, s)
	}

	checkFdList(t, initialFdList, 5, 100*time.Millisecond)
}

func TestAuditSeccomp(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}

	initialFdList := currentFdList(t)

	containerName := "test-local-gadget-auditseccomp001"
	err = localGadgetManager.AddTracer("audit-seccomp", "my-tracer", containerName, "Stream")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}

	seccompProfile := `{"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"action":"SCMP_ACT_LOG","names":["unshare"]}]}`
	runTestContainer(t, containerName, "docker.io/library/alpine", "unshare -i ; echo OK", seccompProfile)

	ch, err := localGadgetManager.Stream("my-tracer", nil)
	if err != nil {
		t.Fatalf("Failed to get stream: %s", err)
	}
	results := <-ch
	if !strings.Contains(results, `"container":"test-local-gadget-auditseccomp001","syscall":"unshare","code":"log"`) {
		t.Fatalf("Failed to get correct Seccomp Audit: %s", results)
	}

	err = localGadgetManager.Delete("my-tracer")
	if err != nil {
		t.Fatalf("Failed to delete tracer: %s", err)
	}

	s := stacks()
	keyword := "audit-seccomp"
	if strings.Contains(s, keyword) {
		t.Fatalf("Error: stack contains %q:\n%s", keyword, s)
	}

	checkFdList(t, initialFdList, 5, 100*time.Millisecond)
}

func TestDNS(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}

	initialFdList := currentFdList(t)

	containerName := "test-local-gadget-dns001"
	err = localGadgetManager.AddTracer("dns", "my-tracer", containerName, "Stream")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}

	runTestContainer(t, containerName, "docker.io/tutum/dnsutils", "dig microsoft.com", "")

	ch, err := localGadgetManager.Stream("my-tracer", nil)
	if err != nil {
		t.Fatalf("Failed to get stream: %s", err)
	}

	var event dnstypes.Event
	var expectedEvent dnstypes.Event
	var result string

	// check that attached message is sent
	result = <-ch
	event = dnstypes.Event{}
	if err := json.Unmarshal([]byte(result), &event); err != nil {
		t.Fatalf("failed to unmarshal json: %s", err)
	}

	expectedEvent = dnstypes.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.DEBUG,
			Message:   "tracer attached",
			Node:      "local",
			Namespace: "default",
			Pod:       "test-local-gadget-dns001",
		},
	}

	if event != expectedEvent {
		t.Fatalf("Received: %v, Expected: %v", event, expectedEvent)
	}

	// check dns request is traced
	result = <-ch
	event = dnstypes.Event{}
	if err := json.Unmarshal([]byte(result), &event); err != nil {
		t.Fatalf("failed to unmarshal json: %s", err)
	}

	expectedEvent = dnstypes.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Node:      "local",
			Namespace: "default",
			Pod:       "test-local-gadget-dns001",
		},
		DNSName: "microsoft.com.",
		PktType: "OUTGOING",
		QType:   "A",
	}

	if event != expectedEvent {
		t.Fatalf("Received: %v, Expected: %v", event, expectedEvent)
	}

	// check that detached message is sent
	result = <-ch
	event = dnstypes.Event{}
	if err := json.Unmarshal([]byte(result), &event); err != nil {
		t.Fatalf("failed to unmarshal json: %s", err)
	}

	expectedEvent = dnstypes.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.DEBUG,
			Message:   "tracer detached",
			Node:      "local",
			Namespace: "default",
			Pod:       "test-local-gadget-dns001",
		},
	}

	if event != expectedEvent {
		t.Fatalf("Received: %v, Expected: %v", event, expectedEvent)
	}

	err = localGadgetManager.Delete("my-tracer")
	if err != nil {
		t.Fatalf("Failed to delete tracer: %s", err)
	}

	s := stacks()
	keyword := "pkg/gadgets/dns/"
	if strings.Contains(s, keyword) {
		t.Fatalf("Error: stack contains %q:\n%s", keyword, s)
	}

	checkFdList(t, initialFdList, 5, 100*time.Millisecond)
}

func TestCollector(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}

	err = localGadgetManager.AddTracer("socket-collector", "my-tracer1", "my-container", "Status")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer1", "collect")
	if err != nil {
		t.Fatalf("Failed to run the tracer: %s", err)
	}
}
