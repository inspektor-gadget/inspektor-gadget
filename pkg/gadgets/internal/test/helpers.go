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

package test

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/go-cmp/cmp"
	"github.com/moby/moby/pkg/parsers/kernel"
	"golang.org/x/sys/unix"
)

// CreateMntNsFilterMap creates and fills an eBPF map that can be used
// to filter by mount namespace in the different tracers.
func CreateMntNsFilterMap(t testing.TB, mountNsIDs ...uint64) *ebpf.Map {
	t.Helper()

	const one = uint32(1)

	mntnsSpec := &ebpf.MapSpec{
		Name:       "filter_map_" + t.Name(),
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 1024,
	}
	m, err := ebpf.NewMap(mntnsSpec)
	if err != nil {
		t.Fatalf("Failed to create eBPF map: %s", err)
	}
	t.Cleanup(func() { m.Close() })

	for _, mountnsid := range mountNsIDs {
		if err := m.Put(mountnsid, one); err != nil {
			m.Close()
			t.Fatalf("Failed to update eBPF map: %s", err)
		}
	}

	return m
}

// RequireRoot skips the test if the not running as root
func RequireRoot(t testing.TB) {
	t.Helper()

	if unix.Getuid() != 0 {
		t.Skip("Test requires root")
	}
}

func RequireKernelVersion(t testing.TB, expectedVersion *kernel.VersionInfo) {
	version, err := kernel.GetKernelVersion()
	if err != nil {
		t.Fatalf("Failed to get kernel version: %s", err)
	}

	if kernel.CompareKernelVersion(*version, *expectedVersion) < 0 {
		t.Skipf("Test requires kernel %s", expectedVersion)
	}
}

func NewRunnerWithTest(t *testing.T, config *RunnerConfig) *Runner {
	t.Helper()

	runner, err := NewRunner(config)
	if err != nil {
		t.Fatalf("Creating runner: %s", err)
	}

	t.Cleanup(runner.Close)

	return runner
}

func RunWithRunner(t *testing.T, runner *Runner, f func() error) {
	t.Helper()

	if err := runner.Run(f); err != nil {
		t.Fatalf("Error generating event: %s", err)
	}
}

type ValidateEventType[Event any, Extra any] func(*testing.T, *RunnerInfo, Extra, []Event)

// ExpectNoEvent doesn't expect any event to be captured by the tracer.
func ExpectNoEvent[Event any, Extra any](t *testing.T, _ *RunnerInfo, _ Extra, events []Event) {
	if len(events) != 0 {
		t.Fatalf("No events are expected")
	}
}

// ExpectAtLeastOneEvent expects that at least one of the captures events matches.
func ExpectAtLeastOneEvent[Event any, Extra any](getEvent func(info *RunnerInfo, extra Extra) *Event) ValidateEventType[Event, Extra] {
	return func(t *testing.T, info *RunnerInfo, extra Extra, events []Event) {
		expectedEvent := getEvent(info, extra)

		for _, event := range events {
			if reflect.DeepEqual(expectedEvent, &event) {
				return
			}
		}

		// Provide extra info when only a single event was captured
		if len(events) == 1 {
			t.Fatalf("Event doesn't match:\n%s",
				cmp.Diff(expectedEvent, &events[0]))
		}
		t.Fatalf("Event wasn't captured")
	}
}

// ExpectOneEvent expects only matching event to be captured.
func ExpectOneEvent[Event any, Extra any](getEvent func(info *RunnerInfo, extra Extra) *Event) ValidateEventType[Event, Extra] {
	return func(t *testing.T, info *RunnerInfo, extra Extra, events []Event) {
		expectedEvent := getEvent(info, extra)

		if len(events) != 1 {
			t.Fatalf("One event expected, found: %d", len(events))
		}

		if !reflect.DeepEqual(expectedEvent, &events[0]) {
			t.Fatalf("Event doesn't match:\n%s",
				cmp.Diff(expectedEvent, &events[0]))
		}
	}
}

// Equal compares if two values are the same.
func Equal[T comparable](t *testing.T, expected, actual T, message string) {
	t.Helper()

	if expected != actual {
		t.Errorf("%s: want: %v; got: %v", message, expected, actual)
	}
}
