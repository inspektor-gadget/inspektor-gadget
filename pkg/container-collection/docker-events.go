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
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const dockerRequestTimeout = 2 * time.Second

type dockerDiscoveryClient interface {
	Events(context.Context, client.EventsListOptions) client.EventsResult
	ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error)
	ContainerInspect(context.Context, string, client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	Close() error
}

type dockerProcess struct {
	pid          uint32
	mntns, netns uint64
	startTicks   uint64
	started      types.Time
}

type dockerDiscovery struct {
	cc      *ContainerCollection
	api     dockerDiscoveryClient
	probe   func(int) (dockerProcess, error)
	timeout time.Duration
	resync  time.Duration
	backoff time.Duration
}

// StartDockerEventDiscovery must follow Initialize and be stopped before Close.
// It is an alternative to OCI runtime hooks, not an additional producer: one
// owner serializes Docker lifecycle changes, including restarts of the same ID.
// All access is to the selected local Engine API Unix socket.
func (cc *ContainerCollection) StartDockerEventDiscovery(socketPath string) (func(), error) {
	if !cc.initialized || cc.closed {
		return nil, errors.New("Docker discovery requires an initialized container collection")
	}
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("Docker discovery requires an absolute Unix socket path")
	}
	dialer := &net.Dialer{Timeout: dockerRequestTimeout}
	transport := &http.Transport{
		ResponseHeaderTimeout: dockerRequestTimeout,
		MaxIdleConns:          6,
		IdleConnTimeout:       30 * time.Second,
	}
	api, err := client.New(
		client.WithHTTPClient(&http.Client{Transport: transport, CheckRedirect: client.CheckRedirect}),
		client.WithHost("unix://"+socketPath),
		client.WithScheme("http"), // HTTP over the selected local Unix socket.
		client.WithDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		return nil, err
	}
	w := &dockerDiscovery{
		cc: cc, api: api, probe: readDockerProcess,
		timeout: dockerRequestTimeout, resync: time.Minute, backoff: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer api.Close()
		w.run(ctx)
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}, nil
}

func (w *dockerDiscovery) run(ctx context.Context) {
	delay := w.backoff
	for ctx.Err() == nil {
		started := time.Now()
		err := w.watch(ctx)
		if ctx.Err() != nil {
			return
		}
		log.Warnf("Docker event discovery interrupted; reconciling after reconnect: %v", err)
		if time.Since(started) >= w.resync {
			delay = w.backoff
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(2*delay, 30*time.Second)
	}
}

func (w *dockerDiscovery) watch(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	// Events returns only after the subscription is established (or failed).
	// Subscribe first so creations during enumeration cannot fall into a gap.
	stream := w.api.Events(ctx, client.EventsListOptions{
		Filters: make(client.Filters).Add("type", "container").
			Add("event", "start", "restart", "die", "stop", "destroy", "pause", "unpause"),
	})
	changes := make(chan string, 256)
	failed := make(chan error, 1)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-stream.Err:
				if !ok || err == nil {
					err = io.EOF
				}
				failed <- err
				return
			case event, ok := <-stream.Messages:
				if !ok {
					failed <- io.EOF
					return
				}
				if !dockerLifecycleEvent(event) {
					continue
				}
				select {
				case changes <- event.Actor.ID:
				default:
					// Never silently lose a lifecycle event. A fresh snapshot
					// repairs a bounded queue overflow without reloading BPF.
					failed <- errors.New("Docker lifecycle event queue is full")
					return
				}
			}
		}
	}()
	defer func() {
		cancel()
		<-drained
		// SDK closes Err after its response body and reader are released.
		for range stream.Err {
		}
	}()
	if err := w.reconcile(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(w.resync)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failed:
			return err
		case id := <-changes:
			// Inspect even stop/die/destroy events: an old event may arrive
			// after this same container ID has already restarted.
			if err := w.syncContainer(ctx, id); err != nil {
				return err
			}
		case <-ticker.C:
			if err := w.reconcile(ctx); err != nil {
				return err
			}
		}
	}
}

func dockerLifecycleEvent(event events.Message) bool {
	if event.Type != events.ContainerEventType || !fullDockerID(event.Actor.ID) {
		return false
	}
	switch event.Action {
	case events.ActionStart, events.ActionRestart, events.ActionDie, events.ActionStop,
		events.ActionDestroy, events.ActionPause, events.ActionUnPause:
		return true
	}
	return false
}

func fullDockerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (w *dockerDiscovery) reconcile(parent context.Context) error {
	// Bound the entire pass as well as each request. A partial/error snapshot
	// never removes an entry merely because it was absent from the response.
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	request, finish := context.WithTimeout(ctx, w.timeout)
	list, err := w.api.ContainerList(request, client.ContainerListOptions{All: true})
	finish()
	if err != nil {
		return err
	}
	ids := make(map[string]bool)
	for _, c := range list.Items {
		if !fullDockerID(c.ID) {
			return errors.New("Docker list returned a non-canonical container ID")
		}
		ids[c.ID] = true
	}
	w.cc.ContainerRange(func(c *Container) {
		if c.Runtime.RuntimeName == types.RuntimeNameDocker {
			ids[c.Runtime.ContainerID] = true
		}
	})
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	slices.Sort(ordered)
	var firstError error
	failures := 0
	for _, id := range ordered {
		if err := w.syncContainer(ctx, id); err != nil {
			if firstError == nil {
				firstError = err
			}
			failures++
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if firstError != nil {
		return fmt.Errorf("reconciling %d Docker containers failed: %w", failures, firstError)
	}
	return nil
}

func (w *dockerDiscovery) inspect(parent context.Context, id string) (container.InspectResponse, error) {
	ctx, cancel := context.WithTimeout(parent, w.timeout)
	defer cancel()
	result, err := w.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return container.InspectResponse{}, err
	}
	c := result.Container
	if c.ID != id || c.State == nil || c.Config == nil {
		return container.InspectResponse{}, errors.New("Docker inspect returned an incomplete or mismatched identity")
	}
	return c, nil
}

func (w *dockerDiscovery) syncContainer(ctx context.Context, id string) error {
	if !fullDockerID(id) {
		return errors.New("Docker discovery refuses non-canonical container IDs")
	}
	if current := w.cc.GetContainer(id); current != nil && current.Runtime.RuntimeName != types.RuntimeNameDocker {
		return errors.New("Docker discovery refuses to replace another runtime's container")
	}
	inspected, err := w.inspect(ctx, id)
	if err != nil {
		if errdefs.IsNotFound(err) {
			w.cc.RemoveContainer(id)
			return nil
		}
		return err
	}
	if !inspected.State.Running || inspected.Config.Labels["io.kubernetes.docker.type"] == "podsandbox" {
		w.cc.RemoveContainer(id)
		return nil
	}
	if inspected.State.Pid <= 0 || inspected.State.Pid > math.MaxUint32 {
		return errors.New("Docker inspect returned an invalid running PID")
	}
	if started, err := time.Parse(time.RFC3339Nano, inspected.State.StartedAt); err != nil || started.IsZero() {
		return errors.New("Docker inspect returned an invalid start time")
	}
	expected, err := w.probe(inspected.State.Pid)
	if err != nil {
		return err
	}
	same := func(c *Container) bool {
		return c.Runtime.RuntimeName == types.RuntimeNameDocker &&
			c.Runtime.ContainerPID == expected.pid && c.Mntns == expected.mntns &&
			c.Netns == expected.netns && c.Runtime.ContainerStartedAt == expected.started
	}
	if current := w.cc.GetContainer(id); current != nil {
		if same(current) {
			return nil
		}
		w.cc.RemoveContainer(id)
	}
	c := &Container{Runtime: RuntimeMetadata{BasicRuntimeMetadata: types.BasicRuntimeMetadata{
		RuntimeName: types.RuntimeNameDocker, ContainerID: id,
		ContainerPID: expected.pid, ContainerStartedAt: expected.started,
		ContainerName:      strings.TrimPrefix(inspected.Name, "/"),
		ContainerImageName: inspected.Config.Image, ContainerImageID: inspected.Image,
	}}, Mntns: expected.mntns, Netns: expected.netns}
	var validationErr error
	w.cc.addContainer(c, func(enriched *Container) bool {
		// Enrichment can take time. Verify both the Engine generation and
		// the process again before publishing anything to namespace filters.
		fresh, err := w.inspect(ctx, id)
		if err != nil {
			validationErr = err
			return false
		}
		actual, err := w.probe(inspected.State.Pid)
		if err != nil {
			validationErr = err
			return false
		}
		if !fresh.State.Running || fresh.State.Pid != inspected.State.Pid ||
			fresh.State.StartedAt != inspected.State.StartedAt || actual != expected || !same(enriched) {
			validationErr = errors.New("Docker process identity changed during enrichment")
			return false
		}
		return true
	})
	if validationErr != nil {
		return validationErr
	}
	if w.cc.GetContainer(id) != c {
		return errors.New("Docker container was rejected during enrichment")
	}
	return nil
}

func readDockerProcess(pid int) (dockerProcess, error) {
	dir, err := os.Open(filepath.Join(host.HostProcFs, strconv.Itoa(pid)))
	if err != nil {
		return dockerProcess{}, err
	}
	defer dir.Close()
	// A proc directory descriptor stays attached to this process even if its
	// numeric PID is subsequently reused. Never combine two process identities.
	base := fmt.Sprintf("/proc/self/fd/%d", dir.Fd())
	ticks := func() (uint64, error) {
		data, err := os.ReadFile(filepath.Join(base, "stat"))
		if err != nil {
			return 0, err
		}
		end := strings.LastIndexByte(string(data), ')')
		fields := strings.Fields(string(data)[end+1:])
		if end < 0 || len(fields) <= 19 {
			return 0, errors.New("invalid process stat")
		}
		return strconv.ParseUint(fields[19], 10, 64)
	}
	before, err := ticks()
	if err != nil {
		return dockerProcess{}, err
	}
	stat, err := dir.Stat()
	if err != nil {
		return dockerProcess{}, err
	}
	mnt, err := os.Stat(filepath.Join(base, "ns/mnt"))
	if err != nil {
		return dockerProcess{}, err
	}
	netns, err := os.Stat(filepath.Join(base, "ns/net"))
	if err != nil {
		return dockerProcess{}, err
	}
	after, err := ticks()
	if err != nil || before != after {
		return dockerProcess{}, errors.New("process changed while reading namespaces")
	}
	return dockerProcess{
		pid: uint32(pid), mntns: mnt.Sys().(*syscall.Stat_t).Ino,
		netns: netns.Sys().(*syscall.Stat_t).Ino, startTicks: before,
		started: types.Time(stat.Sys().(*syscall.Stat_t).Mtim.Nano()),
	}, nil
}
