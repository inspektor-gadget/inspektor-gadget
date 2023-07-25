// Copyright 2022-2023 The Inspektor Gadget authors
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

//go:build linux
// +build linux

package tracer_test

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/types"
)

const controllerPathV2 = "/sys/fs/cgroup/cgroup.controllers"

func TestOOMkillTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})
	require.NotNil(t, tracer, "Returned tracer was nil")
}

func TestOOMkillTracerStopIdempotent(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})

	// Check that a double stop doesn't cause issues
	tracer.Stop()
	tracer.Stop()
}

func TestOOMkillTracer(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	_, err := os.Stat(controllerPathV2)
	if err != nil {
		t.Skip("This test requires cgroup v2 to be mounted: %w", err)
	}

	content, err := os.ReadFile(controllerPathV2)
	if err != nil {
		t.Skipf("Cannot read cgroup v2 controller: %v", err)
	}

	if !strings.Contains(string(content), "memory") {
		t.Skip("This test requires memory controller for cgroup v2")
	}

	cgroupPath := "/sys/fs/cgroup/ig-unit-test-oomkill-tracer"
	memoryLimit := 512 * 1024 // 512 KB.

	// Just in case to clean up everything if the test was interrupted without
	// properly cleaning.
	syscall.Rmdir(cgroupPath)

	// The whole idea of this test is to spawn a child which will allocate so much
	// memory that it get killed by the OOM killer, hence generating an event.
	// We cannot do this in the root cgroup, as it could lead to misbehavior from
	// other test as they would not be able to allocate memory.
	// So, the whole idea is to create a memory cgroup, set the memory.max limit,
	// spawn a process, subscribe this child to the memory cgroup and then
	// allocate the memory until it gets killed.
	err = os.Mkdir(cgroupPath, 0o755)
	require.NoError(t, err, "creating cgroup path %s", cgroupPath)
	defer syscall.Rmdir(cgroupPath)

	memoryMaxPath := fmt.Sprintf("%s/memory.max", cgroupPath)
	file, err := os.OpenFile(memoryMaxPath, os.O_WRONLY, 0)
	require.NoError(t, err, "opening %s", memoryMaxPath)

	_, err = file.Write([]byte(fmt.Sprintf("%d\n", memoryLimit)))
	file.Close()
	require.NoError(t, err, "writing %d to %s", memoryLimit, memoryMaxPath)

	events := make(chan *types.Event)
	eventCallback := func(event *types.Event) {
		// normalize
		event.Timestamp = 0

		events <- event
	}

	runner := utilstest.NewRunnerWithTest(t, nil)

	createTracer(t, &tracer.Config{
		MountnsMap: utilstest.CreateMntNsFilterMap(t, runner.Info.MountNsID),
	}, eventCallback)

	createTracer(t, &tracer.Config{}, eventCallback)

	utilstest.RunWithRunner(t, runner, func() error {
		// Use clone() to make it more portable, at least for amd64 and arm64.
		childPid, _, errno := syscall.Syscall6(syscall.SYS_CLONE, 0, 0, 0, 0, 0, 0)
		require.Equal(t, errno, syscall.Errno(0x0), "spawning child process")

		if childPid == 0 {
			pid := unix.Getpid()
			procsPath := fmt.Sprintf("%s/cgroup.procs", cgroupPath)
			procsFile, err := os.OpenFile(procsPath, os.O_WRONLY, 0)
			require.NoError(t, err, "opening %s", procsPath)

			_, err = procsFile.Write([]byte(fmt.Sprintf("%d\n", pid)))
			procsFile.Close()
			require.NoError(t, err, "writing %d to %s", pid, procsPath)

			// The child is now part of the memory cgroup, let's allocate some memory.
			// The memory will be automatically touched by golang as it will initialize
			// to 0, so no lazy allocation there.
			// As a result, the child should be OOM killed.
			// Let's do it in an infinite loop to ensure the OOM killer is triggered
			// at one moment.
			for {
				_ = make([]byte, memoryLimit*100)
			}

			// This code should never get reached.
			return errors.New("this code should never get reached")
		}

		select {
		case event := <-events:
			require.Equal(t, event.MountNsID, runner.Info.MountNsID, "killed mount namespace ID is not the expected one")
			require.Equal(t, event.KilledComm, path.Base(os.Args[0]), "killed command is not the expected one")
			require.Equal(t, event.KilledPid, uint32(childPid), "killed PID is not the expected one")
		case <-time.After(10 * time.Second):
			t.Fatalf("waiting for OOM kill event from child %d: time out", childPid)
		}

		return nil
	})
}

func createTracer(
	t *testing.T, config *tracer.Config, callback func(*types.Event),
) *tracer.Tracer {
	t.Helper()

	tracer, err := tracer.NewTracer(config, nil, callback)
	require.Nil(t, err, "Error creating tracer: %s", err)
	t.Cleanup(tracer.Stop)

	return tracer
}
