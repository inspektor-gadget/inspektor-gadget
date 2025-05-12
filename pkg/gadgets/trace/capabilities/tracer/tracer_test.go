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
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"testing"
	"time"

	"github.com/moby/moby/pkg/parsers/kernel"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestCapabilitiesTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})
	if tracer == nil {
		t.Fatal("Returned tracer was nil")
	}
}

func TestTraceCapabilitiesTracerStopIdempotent(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})

	// Check that a double stop doesn't cause issues
	tracer.Stop()
	tracer.Stop()
}

func TestCapabilitiesTracer(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)
	// Needs kernel >= 5.1.0 because it introduced the InsetID field.
	utilstest.RequireKernelVersion(t, &kernel.VersionInfo{Kernel: 5, Major: 1, Minor: 0})

	const unprivilegedUID = int(1234)
	const unprivilegedGID = int(5678)

	false_ := false

	type testDefinition struct {
		getTracerConfig func(info *utilstest.RunnerInfo) *tracer.Config
		runnerConfig    *utilstest.RunnerConfig
		generateEvent   func() error
		validateEvent   func(t *testing.T, info *utilstest.RunnerInfo, _ interface{}, events []types.Event)
	}

	for name, test := range map[string]testDefinition{
		"captures_all_events_with_no_filters_configured": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{}
			},
			generateEvent: chown,
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, _ interface{}) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type:      eventtypes.NORMAL,
						Timestamp: 1,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Syscall:       "fchownat",
					CapName:       "CHOWN",
					Cap:           0,
					Audit:         1,
					InsetID:       &false_,
					Verdict:       "Allow",
					CurrentUserNs: info.UserNsID,
					TargetUserNs:  info.UserNsID,
					Caps:          0,
					CapsNames:     []string{},
				}
			}),
		},
		"captures_no_events_with_no_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, 0),
				}
			},
			generateEvent: chown,
			validateEvent: utilstest.ExpectNoEvent[types.Event, interface{}],
		},
		"captures_events_with_matching_filter_CAP_CHOWN": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: chown,
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, _ interface{}) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type:      eventtypes.NORMAL,
						Timestamp: 1,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Syscall:       "fchownat",
					CapName:       "CHOWN",
					Cap:           0,
					Audit:         1,
					InsetID:       &false_,
					Verdict:       "Allow",
					CurrentUserNs: info.UserNsID,
					TargetUserNs:  info.UserNsID,
					Caps:          0,
					CapsNames:     []string{},
				}
			}),
		},
		"captures_events_with_matching_filter_CAP_NET_BIND_SERVICE": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: bind,
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, _ interface{}) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type:      eventtypes.NORMAL,
						Timestamp: 1,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Syscall:       "bind",
					CapName:       "NET_BIND_SERVICE",
					Cap:           10,
					Audit:         1,
					InsetID:       &false_,
					Verdict:       "Allow",
					CurrentUserNs: info.UserNsID,
					TargetUserNs:  info.UserNsID,
					Caps:          0,
					CapsNames:     []string{},
				}
			}),
		},
		"verdict_deny": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			runnerConfig: &utilstest.RunnerConfig{Uid: 1245},
			generateEvent: func() error {
				if err := chown(); err == nil {
					return fmt.Errorf("chown should have failed")
				}
				return nil
			},
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, _ interface{}) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type:      eventtypes.NORMAL,
						Timestamp: 1,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Syscall:       "fchownat",
					CapName:       "CHOWN",
					Cap:           0,
					Audit:         1,
					InsetID:       &false_,
					Verdict:       "Deny",
					CurrentUserNs: info.UserNsID,
					TargetUserNs:  info.UserNsID,
					Caps:          0,
					CapsNames:     []string{},
				}
			}),
		},
		"audit_only_false": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					AuditOnly:  false,
				}
			},
			generateEvent: generateNonAudit,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ interface{}, events []types.Event) {
				for _, event := range events {
					if event.Audit == 0 {
						return
					}
				}

				t.Fatal("No audit event was captured")
			},
		},
		"audit_only_true": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					AuditOnly:  true,
				}
			},
			generateEvent: generateNonAudit,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ interface{}, events []types.Event) {
				for _, event := range events {
					if event.Audit == 0 {
						t.Fatal("No audit event was captured")
					}
				}
			},
		},
		"unique_false": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					Unique:     false,
				}
			},
			generateEvent: repeatChown,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ interface{}, events []types.Event) {
				nfound := 0
				for _, event := range events {
					if event.CapName == "CHOWN" {
						nfound++
					}
				}

				if nfound <= 1 {
					t.Fatalf("Capability not found")
				}
			},
		},
		"unique_true": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					Unique:     true,
				}
			},
			generateEvent: repeatChown,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ interface{}, events []types.Event) {
				nfound := 0
				for _, event := range events {
					if event.CapName == "CHOWN" {
						nfound++
					}
				}

				if nfound == 0 {
					t.Fatalf("Capability not found")
				}

				if nfound > 1 {
					t.Fatalf("Capability not unique: found %d times", nfound)
				}
			},
		},
		"event_has_UID_and_GID_of_user_generating_event": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			runnerConfig: &utilstest.RunnerConfig{
				Uid: unprivilegedUID,
				Gid: unprivilegedGID,
			},
			generateEvent: func() error {
				if err := chown(); err == nil {
					return fmt.Errorf("chown should have failed")
				}
				return nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ interface{}, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Two events expected. %d received", len(events))
				}

				utilstest.Equal(t, uint32(info.Uid), events[0].Uid,
					"Event has bad UID")
				utilstest.Equal(t, uint32(info.Gid), events[0].Gid,
					"Event has bad GID")
			},
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			events := []types.Event{}
			eventCallback := func(event *types.Event) {
				// normalize
				if event.Timestamp != 0 {
					event.Timestamp = 1
				}
				event.Caps = 0
				event.CapsNames = []string{}

				events = append(events, *event)
			}

			runner := utilstest.NewRunnerWithTest(t, test.runnerConfig)

			createTracer(t, test.getTracerConfig(runner.Info), eventCallback)

			utilstest.RunWithRunner(t, runner, test.generateEvent)

			// Give some time for the tracer to capture the events
			time.Sleep(100 * time.Millisecond)

			test.validateEvent(t, runner.Info, 0, events)
		})
	}
}

func TestCapabilitiesTracerMultipleMntNsIDsFilter(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	events := []types.Event{}
	eventCallback := func(event *types.Event) {
		// normalize
		event.Timestamp = 0

		events = append(events, *event)
	}

	// struct with only fields we want to check on this test
	type expectedEvent struct {
		mntNsID uint64
	}

	const n int = 5
	runners := make([]*utilstest.Runner, n)
	expectedEvents := make([]expectedEvent, n)
	mntNsIDs := make([]uint64, n)

	for i := 0; i < n; i++ {
		runners[i] = utilstest.NewRunnerWithTest(t, nil)
		mntNsIDs[i] = runners[i].Info.MountNsID
		expectedEvents[i].mntNsID = runners[i].Info.MountNsID
	}

	// Filter events from all runners but last one
	config := &tracer.Config{
		MountnsMap: utilstest.CreateMntNsFilterMap(t, mntNsIDs[:n-1]...),
		AuditOnly:  true,
	}

	createTracer(t, config, eventCallback)

	for i := 0; i < n; i++ {
		utilstest.RunWithRunner(t, runners[i], bind)
	}

	// Give some time for the tracer to capture the events
	time.Sleep(100 * time.Millisecond)

	if len(events) != n-1 {
		t.Fatalf("%d events were expected, %d found", n-1, len(events))
	}

	// Pop last event since it shouldn't have been captured
	expectedEvents = expectedEvents[:n-1]

	// Order of events is not guaranteed, then we need to sort before comparing
	sort.Slice(expectedEvents, func(i, j int) bool {
		return expectedEvents[i].mntNsID < expectedEvents[j].mntNsID
	})
	sort.Slice(events, func(i, j int) bool {
		return events[i].MountNsID < events[j].MountNsID
	})

	for i := 0; i < n-1; i++ {
		utilstest.Equal(t, expectedEvents[i].mntNsID, events[i].MountNsID,
			"Captured event has bad MountNsID")

		utilstest.Equal(t, "NET_BIND_SERVICE", events[i].CapName,
			"Captured event has bad CapName")
	}
}

func createTracer(
	t *testing.T, config *tracer.Config, callback func(*types.Event),
) *tracer.Tracer {
	t.Helper()

	tracer, err := tracer.NewTracer(config, nil, callback)
	if err != nil {
		t.Fatalf("Error creating tracer: %s", err)
	}
	t.Cleanup(tracer.Stop)

	return tracer
}

func generateNonAudit() error {
	// This command will generate some non-audit capabilities checks
	// https://github.com/torvalds/linux/blob/84368d882b9688bfac77ce48d33b1e20a4e4a787/kernel/kallsyms.c#L899
	// If TestCapabilitiesTracer/audit_only_false fails we should
	// check that this command is actually generating those checks
	cmd := exec.Command("/bin/cat", "/proc/kallsyms")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running command: %w", err)
	}

	return nil
}

func repeatChown() error {
	for i := 0; i < 5; i++ {
		if err := chown(); err != nil {
			return err
		}
	}

	return nil
}

// chown requires CAP_CHOWN
func chown() error {
	file, err := os.CreateTemp("/tmp", "prefix")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name())

	return unix.Chown(file.Name(), 1000, 1000)
}

// bind requires CAP_NET_BIND_SERVICE as it binds to a port less than 1024
func bind() error {
	ipStr := "127.0.0.1"
	domain := unix.AF_INET
	typ := unix.SOCK_STREAM
	port := 555

	fd, err := unix.Socket(domain, typ, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var sa unix.Sockaddr

	ip := net.ParseIP(ipStr)

	if ip.To4() != nil {
		sa4 := &unix.SockaddrInet4{Port: port}
		copy(sa4.Addr[:], ip.To4())
		sa = sa4
	} else if ip.To16() != nil {
		sa6 := &unix.SockaddrInet6{Port: port}
		copy(sa6.Addr[:], ip.To16())
		sa = sa6
	} else {
		return fmt.Errorf("invalid IP address")
	}

	if err := unix.Bind(fd, sa); err != nil {
		return fmt.Errorf("Bind: %w", err)
	}

	return nil
}
