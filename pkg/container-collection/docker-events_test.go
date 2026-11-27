// Copyright 2026 The Inspektor Gadget authors
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

package containercollection

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var dockerTestID = strings.Repeat("a", 64)

type fakeDockerStream struct {
	messages chan events.Message
	errs     chan error
}

type fakeDockerDiscoveryAPI struct {
	mu          sync.Mutex
	containers  map[string]container.InspectResponse
	processes   map[int]dockerProcess
	streams     chan fakeDockerStream
	inspectErr  error
	listErr     error
	inspectHook func(*container.InspectResponse)
	listHook    func(context.Context)
	subscribed  bool
}

func (f *fakeDockerDiscoveryAPI) Events(ctx context.Context, _ client.EventsListOptions) client.EventsResult {
	stream := fakeDockerStream{make(chan events.Message, 600), make(chan error, 1)}
	f.mu.Lock()
	f.subscribed = true
	f.mu.Unlock()
	f.streams <- stream
	go func() {
		<-ctx.Done()
		close(stream.errs)
	}()
	return client.EventsResult{Messages: stream.messages, Err: stream.errs}
}

func (f *fakeDockerDiscoveryAPI) ContainerList(ctx context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
	f.mu.Lock()
	hook := f.listHook
	f.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.subscribed {
		return client.ContainerListResult{}, errors.New("snapshot preceded subscription")
	}
	out := client.ContainerListResult{}
	for id := range f.containers {
		out.Items = append(out.Items, container.Summary{ID: id})
	}
	return out, f.listErr
}

func (f *fakeDockerDiscoveryAPI) ContainerInspect(_ context.Context, id string, _ client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inspectErr != nil {
		return client.ContainerInspectResult{}, f.inspectErr
	}
	c, ok := f.containers[id]
	if !ok {
		return client.ContainerInspectResult{}, errdefs.ErrNotFound
	}
	state := *c.State
	c.State = &state
	if f.inspectHook != nil {
		f.inspectHook(&c)
	}
	return client.ContainerInspectResult{Container: c}, nil
}

func (f *fakeDockerDiscoveryAPI) Close() error { return nil }

func (f *fakeDockerDiscoveryAPI) probe(pid int) (dockerProcess, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.processes[pid]
	if !ok {
		return dockerProcess{}, os.ErrNotExist
	}
	return p, nil
}

func (f *fakeDockerDiscoveryAPI) put(id string, pid int, generation int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.containers[id] = container.InspectResponse{
		ID: id, Name: "/test", Image: "sha256:test",
		Config: &container.Config{Image: "test", Labels: map[string]string{}},
		State: &container.State{
			Running: true, Pid: pid,
			StartedAt: time.Unix(generation, 0).UTC().Format(time.RFC3339Nano),
		},
	}
	f.processes[pid] = dockerProcess{
		pid: uint32(pid), mntns: uint64(generation + 100), netns: uint64(generation + 200),
		startTicks: uint64(generation), started: types.Time(generation),
	}
}

func testDockerDiscovery(t *testing.T) (*dockerDiscovery, *fakeDockerDiscoveryAPI) {
	t.Helper()
	cc := &ContainerCollection{}
	if err := cc.Initialize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cc.Close)
	api := &fakeDockerDiscoveryAPI{
		containers: make(map[string]container.InspectResponse), processes: make(map[int]dockerProcess),
		streams: make(chan fakeDockerStream, 10),
	}
	return &dockerDiscovery{
		cc: cc, api: api, probe: api.probe,
		timeout: 100 * time.Millisecond, resync: time.Hour, backoff: time.Millisecond,
	}, api
}

func waitDocker(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for Docker discovery")
}

func TestDockerDiscoveryRestartAndLateStop(t *testing.T) {
	w, api := testDockerDiscovery(t)
	api.put(dockerTestID, 10, 1)
	if err := w.syncContainer(context.Background(), dockerTestID); err != nil {
		t.Fatal(err)
	}
	first := w.cc.GetContainer(dockerTestID)
	api.put(dockerTestID, 11, 2)
	if err := w.syncContainer(context.Background(), dockerTestID); err != nil {
		t.Fatal(err)
	}
	restarted := w.cc.GetContainer(dockerTestID)
	if restarted == first || restarted.Runtime.ContainerPID != 11 || w.cc.LookupContainerByMntns(first.Mntns) != nil {
		t.Fatal("restart did not replace the old namespace identity")
	}
	// A delayed stop event is reconciled against the currently running state.
	if err := w.syncContainer(context.Background(), dockerTestID); err != nil {
		t.Fatal(err)
	}
	if w.cc.GetContainer(dockerTestID) != restarted {
		t.Fatal("late event replaced the current process")
	}
	// Even reuse of the numeric PID has a new start and namespace identity.
	api.put(dockerTestID, 11, 3)
	if err := w.syncContainer(context.Background(), dockerTestID); err != nil {
		t.Fatal(err)
	}
	if w.cc.GetContainer(dockerTestID) == restarted {
		t.Fatal("PID reuse was missed")
	}
}

func TestDockerDiscoveryKeepsEntriesOnErrorsAndRemovesConfirmedMissing(t *testing.T) {
	w, api := testDockerDiscovery(t)
	api.put(dockerTestID, 10, 1)
	if err := w.syncContainer(context.Background(), dockerTestID); err != nil {
		t.Fatal(err)
	}
	original := w.cc.GetContainer(dockerTestID)
	api.inspectErr = context.DeadlineExceeded
	if err := w.syncContainer(context.Background(), dockerTestID); err == nil || w.cc.GetContainer(dockerTestID) != original {
		t.Fatal("transient inspect failure changed the collection")
	}
	api.inspectErr = nil
	api.subscribed = true
	api.listErr = errors.New("incomplete snapshot")
	delete(api.containers, dockerTestID)
	if err := w.reconcile(context.Background()); err == nil || w.cc.GetContainer(dockerTestID) != original {
		t.Fatal("failed snapshot removed a container")
	}
	api.listErr = nil
	if err := w.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.cc.GetContainer(dockerTestID) != nil || w.cc.LookupContainerByMntns(original.Mntns) != nil {
		t.Fatal("confirmed missing container was retained")
	}
}

func TestDockerDiscoveryVanishingContainerDoesNotBlockOtherIdentities(t *testing.T) {
	w, api := testDockerDiscovery(t)
	api.subscribed = true
	api.put(dockerTestID, 10, 1)
	delete(api.processes, 10)
	other := strings.Repeat("b", 64)
	api.put(other, 11, 2)
	if err := w.reconcile(context.Background()); err == nil {
		t.Fatal("vanishing process should require a later reconciliation")
	}
	if w.cc.GetContainer(dockerTestID) != nil || w.cc.GetContainer(other) == nil {
		t.Fatal("one vanishing process blocked a healthy container")
	}
}

func TestDockerDiscoveryRejectsIdentityChangesBeforePublishing(t *testing.T) {
	for _, mutation := range []string{"engine-generation", "process-generation", "enriched-namespace", "inspect-id", "short-id"} {
		t.Run(mutation, func(t *testing.T) {
			w, api := testDockerDiscovery(t)
			api.put(dockerTestID, 10, 1)
			calls := 0
			api.inspectHook = func(c *container.InspectResponse) {
				calls++
				if mutation == "inspect-id" {
					c.ID = strings.Repeat("b", 64)
				}
				if calls == 2 {
					if mutation == "engine-generation" {
						c.State.StartedAt = time.Unix(2, 0).UTC().Format(time.RFC3339Nano)
					}
					if mutation == "process-generation" {
						p := api.processes[10]
						p.startTicks++
						api.processes[10] = p
					}
				}
			}
			if mutation == "enriched-namespace" {
				w.cc.containerEnrichers = append(w.cc.containerEnrichers, func(c *Container) bool {
					c.Mntns++
					return true
				})
			}
			id := dockerTestID
			if mutation == "short-id" {
				id = id[:12]
			}
			if err := w.syncContainer(context.Background(), id); err == nil {
				t.Fatal("changed identity was accepted")
			}
			if w.cc.ContainerLen() != 0 {
				t.Fatal("invalid identity was published")
			}
		})
	}
}

func TestDockerDiscoveryReconnectRepairsMissedEvents(t *testing.T) {
	w, api := testDockerDiscovery(t)
	api.put(dockerTestID, 10, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	stream := <-api.streams
	waitDocker(t, func() bool { return w.cc.GetContainer(dockerTestID) != nil })
	other := strings.Repeat("b", 64)
	api.mu.Lock()
	delete(api.containers, dockerTestID)
	api.mu.Unlock()
	api.put(other, 11, 2)
	stream.errs <- io.EOF
	select {
	case <-api.streams:
	case <-time.After(3 * time.Second):
		t.Fatal("event subscription was not re-established")
	}
	waitDocker(t, func() bool { return w.cc.GetContainer(other) != nil && w.cc.GetContainer(dockerTestID) == nil })
}

func TestDockerDiscoveryEventsDuringSnapshotAndCancellation(t *testing.T) {
	w, api := testDockerDiscovery(t)
	entered, release := make(chan struct{}), make(chan struct{})
	api.listHook = func(ctx context.Context) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.watch(ctx) }()
	stream := <-api.streams
	<-entered
	api.put(dockerTestID, 10, 1)
	stream.messages <- events.Message{Type: events.ContainerEventType, Action: events.ActionStart, Actor: events.Actor{ID: dockerTestID}}
	close(release)
	waitDocker(t, func() bool { return w.cc.GetContainer(dockerTestID) != nil })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release the event reader")
	}
}

func TestDockerDiscoveryQueueOverflowRequiresReconciliation(t *testing.T) {
	w, api := testDockerDiscovery(t)
	entered, release := make(chan struct{}), make(chan struct{})
	api.listHook = func(ctx context.Context) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.watch(ctx) }()
	stream := <-api.streams
	<-entered
	for i := 0; i < 300; i++ {
		stream.messages <- events.Message{Type: events.ContainerEventType, Action: events.ActionStart, Actor: events.Actor{ID: dockerTestID}}
	}
	waitDocker(t, func() bool { return len(stream.messages) < 44 })
	close(release)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "queue is full") {
			t.Fatalf("overflow was not reported: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("overflow did not terminate the subscription")
	}
}

func TestDockerDiscoveryLifecycleFilter(t *testing.T) {
	for _, action := range []events.Action{events.ActionStart, events.ActionRestart, events.ActionDie, events.ActionStop, events.ActionDestroy, events.ActionPause, events.ActionUnPause} {
		if !dockerLifecycleEvent(events.Message{Type: events.ContainerEventType, Action: action, Actor: events.Actor{ID: dockerTestID}}) {
			t.Fatal("lifecycle event ignored", action)
		}
	}
	for _, event := range []events.Message{
		{Type: events.ImageEventType, Action: events.ActionDestroy, Actor: events.Actor{ID: dockerTestID}},
		{Type: events.ContainerEventType, Action: events.ActionStart, Actor: events.Actor{ID: dockerTestID[:12]}},
		{Type: events.ContainerEventType, Action: events.ActionExecStart, Actor: events.Actor{ID: dockerTestID}},
	} {
		if dockerLifecycleEvent(event) {
			t.Fatal("unrelated event accepted", event)
		}
	}
}

func TestDockerDiscoveryUnixAPIAndOwnedShutdown(t *testing.T) {
	cc := &ContainerCollection{}
	if err := cc.Initialize(); err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	inspected := container.InspectResponse{
		ID: dockerTestID, Name: "/mock", Config: &container.Config{Image: "mock"},
		State: &container.State{Running: true, Pid: os.Getpid(), StartedAt: time.Now().UTC().Format(time.RFC3339Nano)},
	}
	server := &http.Server{Handler: http.HandlerFunc(func(out http.ResponseWriter, req *http.Request) {
		out.Header().Set("API-Version", "1.56")
		path := req.URL.Path
		switch {
		case strings.HasSuffix(path, "/_ping"):
			_, _ = io.WriteString(out, "OK")
		case strings.HasSuffix(path, "/events"):
			out.Header().Set("Content-Type", "application/json")
			out.WriteHeader(http.StatusOK)
			out.(http.Flusher).Flush()
			<-req.Context().Done()
		case strings.HasSuffix(path, "/containers/json"):
			_ = json.NewEncoder(out).Encode([]container.Summary{{ID: dockerTestID}})
		case strings.HasSuffix(path, "/containers/"+dockerTestID+"/json"):
			_ = json.NewEncoder(out).Encode(inspected)
		default:
			http.NotFound(out, req)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	stop, err := cc.StartDockerEventDiscovery(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	waitDocker(t, func() bool { return cc.GetContainer(dockerTestID) != nil })
	finished := make(chan struct{})
	go func() { stop(); stop(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("owned watcher shutdown did not finish")
	}
}
