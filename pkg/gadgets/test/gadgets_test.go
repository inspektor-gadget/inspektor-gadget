//go:build linux
// +build linux

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

package gadgets_test

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
)

// Function to generate an event used most of the times.
// Returns pid of executed process.
func generateEvent(cmdName string) error {
	cmd := exec.Command("/bin/"+cmdName, "/dev/null")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running command: %w", err)
	}

	return nil
}

func createTestEnv(
	t *testing.T,
	traceName string,
	containerName string,
	eventCallback func(event *types.Event),
) *containercollection.ContainerCollection {
	t.Helper()

	cc := &containercollection.ContainerCollection{}

	tc, err := tracercollection.NewTracerCollection(cc)
	if err != nil {
		t.Fatalf("failed to create tracer collection: %s", err)
	}
	t.Cleanup(tc.Close)

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithTracerCollection(tc),
	}

	if err := cc.Initialize(opts...); err != nil {
		t.Fatalf("failed to init container collection: %s", err)
	}
	t.Cleanup(cc.Close)

	containerSelector := containercollection.ContainerSelector{
		Name: containerName,
	}
	if err := tc.AddTracer(traceName, containerSelector); err != nil {
		t.Fatalf("error adding tracer: %s", err)
	}
	t.Cleanup(func() { tc.RemoveTracer(traceName) })

	// Get mount namespace map to filter by containers
	mountnsmap, err := tc.TracerMountNsMap(traceName)
	if err != nil {
		t.Fatalf("failed to get mountnsmap: %s", err)
	}

	// Create the tracer
	tracer, err := tracer.NewTracer(&tracer.Config{MountnsMap: mountnsmap}, cc, eventCallback)
	if err != nil {
		t.Fatalf("failed to create tracer: %s", err)
	}
	t.Cleanup(tracer.Stop)

	return cc
}

// TestContainerRemovalRaceCondition checks that a container is removed
// from the mount ns inode ids map fast enough to avoid capturing events
// from the wrong container. See
// https://github.com/inspektor-gadget/inspektor-gadget/issues/1001
func TestContainerRemovalRaceCondition(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const (
		traceName            = "trace_exec"
		matchingContainer    = "foo"
		nonMatchingContainer = "bar"
		matchingCommand      = "cat"
		nonMatchingCommand   = "touch"
	)

	eventCallback := func(event *types.Event) {
		// "nonMatchingCommand" is only executed in the
		// "nonMatching" container that doesn't match with the
		// filter
		if event.Comm == nonMatchingCommand {
			t.Fatalf("bad event captured")
		}
	}

	cc := createTestEnv(t, traceName, matchingContainer, eventCallback)

	runContainerTest := func(
		cc *containercollection.ContainerCollection,
		name string,
		f func() error,
		iterations int,
	) error {
		for i := 0; i < iterations; i++ {
			r, err := utilstest.NewRunner(&utilstest.RunnerConfig{})
			if err != nil {
				return fmt.Errorf("failed to create runner: %w", err)
			}

			container := &containercollection.Container{
				ID:    uuid.New().String(),
				Name:  name,
				Mntns: r.Info.MountNsID,
				Pid:   uint32(r.Info.Tid),
			}

			cc.AddContainer(container)

			if err := r.Run(f); err != nil {
				return fmt.Errorf("failed to run command: %w", err)
			}

			r.Close()

			// Use a delay to simulate the time it requires Inspektor Gadget to remove the
			// container after it's notified. Notice that the container hooks are not blocking
			// on the remove events, hence when we get the notification the container is already
			// gone.
			time.AfterFunc(1*time.Millisecond, func() { cc.RemoveContainer(container.ID) })
		}

		return nil
	}

	const n = 1000

	errs, _ := errgroup.WithContext(context.TODO())

	errs.Go(func() error {
		catDevNull := func() error { return generateEvent(matchingCommand) }
		return runContainerTest(cc, matchingContainer, catDevNull, n)
	})
	errs.Go(func() error {
		touchDevNull := func() error { return generateEvent(nonMatchingCommand) }
		return runContainerTest(cc, nonMatchingContainer, touchDevNull, n)
	})

	if err := errs.Wait(); err != nil {
		t.Fatalf("failed generating events: %s", err)
	}
}

// TestEventEnrichmentRaceCondition checks that an event is properly enriched when the generating
// container is removed soon after it generates the event.
// https://github.com/inspektor-gadget/inspektor-gadget/issues/1178
func TestEventEnrichmentRaceCondition(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const (
		traceName     = "trace_exec"
		containerName = "foo"
		command       = "cat"
	)

	eventCallback := func(event *types.Event) {
		if event.Container == "" {
			t.Fatal("event not enriched")
		}
	}

	cc := createTestEnv(t, traceName, containerName, eventCallback)

	const n = 1000

	errs, _ := errgroup.WithContext(context.TODO())

	runContainerTest := func(
		cc *containercollection.ContainerCollection,
		name string,
		f func() error,
		iterations int,
	) error {
		for i := 0; i < iterations; i++ {
			r, err := utilstest.NewRunner(&utilstest.RunnerConfig{})
			if err != nil {
				return fmt.Errorf("failed to create runner: %w", err)
			}

			container := &containercollection.Container{
				ID:    uuid.New().String(),
				Name:  name,
				Mntns: r.Info.MountNsID,
				Pid:   uint32(r.Info.Tid),
			}

			cc.AddContainer(container)
			// Remove the container right after it generates the command. Running this
			// after r.Run() will be too late, so let's do in a different goroutine to
			// have some time.
			go func() { cc.RemoveContainer(container.ID) }()

			if err := r.Run(f); err != nil {
				return fmt.Errorf("failed to run command: %w", err)
			}

			r.Close()
		}

		return nil
	}

	errs.Go(func() error {
		catDevNull := func() error { return generateEvent(command) }
		return runContainerTest(cc, containerName, catDevNull, n)
	})

	if err := errs.Wait(); err != nil {
		t.Fatalf("failed generating events: %s", err)
	}
}
