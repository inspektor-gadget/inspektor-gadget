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
	"net"
	"sort"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestBindTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})
	if tracer == nil {
		t.Fatal("Returned tracer was nil")
	}
}

func TestBindTracerStopIdempotent(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})

	// Check that a double stop doesn't cause issues
	tracer.Stop()
	tracer.Stop()
}

type sockOpt struct {
	level int
	opt   int
	value int
}

func TestBindTracer(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const unprivilegedUID = int(1435)
	const unprivilegedGID = int(6789)

	type testDefinition struct {
		getTracerConfig func(info *utilstest.RunnerInfo) *tracer.Config
		runnerConfig    *utilstest.RunnerConfig
		generateEvent   func() (uint16, error)
		validateEvent   func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event)
	}

	for name, test := range map[string]testDefinition{
		"captures_all_events_with_no_filters_configured": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{}
			},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, port uint16) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Pid:           uint32(info.Pid),
					Comm:          info.Comm,
					Protocol:      "TCP",
					Addr:          "127.0.0.1",
					Port:          port,
					Options:       ".....",
					Interface:     "",
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
				}
			}),
		},
		"captures_no_events_with_no_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, 0),
				}
			},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			validateEvent: utilstest.ExpectNoEvent[types.Event, uint16],
		},
		"captures_events_with_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, port uint16) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Pid:           uint32(info.Pid),
					Comm:          info.Comm,
					Protocol:      "TCP",
					Addr:          "127.0.0.1",
					Port:          port,
					Options:       ".....",
					Interface:     "",
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
				}
			}),
		},
		"tcp4": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: bindSocketFn("127.0.0.2", unix.AF_INET, unix.SOCK_STREAM, 0),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
				}

				utilstest.Equal(t, "127.0.0.2", events[0].Addr, "Captured event has bad Addr")
				utilstest.Equal(t, "TCP", events[0].Protocol, "Captured event has bad Protocol")
			},
		},
		"tcp6": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: bindSocketFn("::", unix.AF_INET6, unix.SOCK_STREAM, 0),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
				}

				utilstest.Equal(t, "::", events[0].Addr, "Captured event has bad Addr")
				utilstest.Equal(t, "TCP", events[0].Protocol, "Captured event has bad Protocol")
			},
		},
		"udp4": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_DGRAM, 0),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
				}

				utilstest.Equal(t, "127.0.0.1", events[0].Addr, "Captured event has bad Addr")
				utilstest.Equal(t, "UDP", events[0].Protocol, "Captured event has bad Protocol")
			},
		},
		"udp6": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: bindSocketFn("::", unix.AF_INET6, unix.SOCK_DGRAM, 0),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
				}

				utilstest.Equal(t, "::", events[0].Addr, "Captured event has bad Addr")
				utilstest.Equal(t, "UDP", events[0].Protocol, "Captured event has bad Protocol")
			},
		},
		"interface": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: func() (uint16, error) {
				opts := []sockOpt{
					{
						level: unix.SOL_SOCKET,
						opt:   unix.SO_BINDTOIFINDEX,
						value: 1, // "lo" iface
					},
				}

				return bindSocketWithOpts("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0, opts)
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
				}

				utilstest.Equal(t, "lo", events[0].Interface, "Captured event has bad Interface")
			},
		},
		"pid_filter_match": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					TargetPid: int32(info.Pid),
					// It's difficult to only test the PID filter since other
					// test events are generated from the same PID on this
					// test suite
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
				}
			},
		},
		"pid_filter_no_match": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					TargetPid:  int32(1),
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			validateEvent: utilstest.ExpectNoEvent[types.Event, uint16],
		},
		"target_ports_filter_match": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap:  utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					TargetPorts: []uint16{5555},
				}
			},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 5555),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
				}
			},
		},
		"target_ports_filter_no_match": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap:  utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					TargetPorts: []uint16{5555},
				}
			},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 5556),
			validateEvent: utilstest.ExpectNoEvent[types.Event, uint16],
		},
		"target_ports_filter_multiple_ports": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap:  utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					TargetPorts: []uint16{5555, 5556, 5557, 5558},
				}
			},
			generateEvent: func() (uint16, error) {
				// Generate 5 events but only 4 should be captured
				ports := []uint16{5555, 5556, 5557, 5558, 5559}
				var err error
				for _, port := range ports {
					_, err = bindSocket("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, int(port))
					if err != nil {
						return 0, err
					}
				}

				return 0, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 4 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
				}
			},
		},
		"ignore_errors_false": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap:   utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					IgnoreErrors: false,
				}
			},
			generateEvent: bindSocketError,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 2 {
					t.Fatalf("Wrong number of events received %d, expected 2", len(events))
				}
			},
		},
		"ignore_errors_true": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap:   utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					IgnoreErrors: true,
				}
			},
			generateEvent: bindSocketError,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, port uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("Wrong number of events received %d, expected 1", len(events))
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
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ uint16, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("One event expected")
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
				event.Timestamp = 0

				events = append(events, *event)
			}

			runner := utilstest.NewRunnerWithTest(t, test.runnerConfig)

			createTracer(t, test.getTracerConfig(runner.Info), eventCallback)

			var port uint16

			utilstest.RunWithRunner(t, runner, func() error {
				var err error
				port, err = test.generateEvent()
				return err
			})

			// Give some time for the tracer to capture the events
			time.Sleep(100 * time.Millisecond)

			test.validateEvent(t, runner.Info, port, events)
		})
	}
}

func TestBindTracerOpts(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	type testDefinition struct {
		opts         []sockOpt
		expectedOpts string
	}

	for name, test := range map[string]testDefinition{
		"no_options": {
			opts:         nil,
			expectedOpts: ".....",
		},
		"SO_REUSEPORT": {
			opts: []sockOpt{
				{
					level: unix.SOL_SOCKET,
					opt:   unix.SO_REUSEPORT,
					value: 1,
				},
			},
			expectedOpts: "r....",
		},
		"SO_REUSEADDR": {
			opts: []sockOpt{
				{
					level: unix.SOL_SOCKET,
					opt:   unix.SO_REUSEADDR,
					value: 1,
				},
			},
			expectedOpts: ".R...",
		},
		"IP_TRANSPARENT": {
			opts: []sockOpt{
				{
					level: unix.IPPROTO_IP,
					opt:   unix.IP_TRANSPARENT,
					value: 1,
				},
			},
			expectedOpts: "...T.",
		},
		"IP_BIND_ADDRESS_NO_PORT": {
			opts: []sockOpt{
				{
					level: unix.IPPROTO_IP,
					opt:   unix.IP_BIND_ADDRESS_NO_PORT,
					value: 1,
				},
			},
			expectedOpts: "..N..",
		},
		"IP_FREEBIND": {
			opts: []sockOpt{
				{
					level: unix.IPPROTO_IP,
					opt:   unix.IP_FREEBIND,
					value: 1,
				},
			},
			expectedOpts: "....F",
		},
		"SO_REUSEPORT|SO_REUSEADDR": {
			opts: []sockOpt{
				{
					level: unix.SOL_SOCKET,
					opt:   unix.SO_REUSEPORT,
					value: 1,
				},
				{
					level: unix.SOL_SOCKET,
					opt:   unix.SO_REUSEADDR,
					value: 1,
				},
			},
			expectedOpts: "rR...",
		},
		"IP_TRANSPARENT|IP_BIND_ADDRESS_NO_PORT|IP_FREEBIND": {
			opts: []sockOpt{
				{
					level: unix.IPPROTO_IP,
					opt:   unix.IP_TRANSPARENT,
					value: 1,
				},
				{
					level: unix.IPPROTO_IP,
					opt:   unix.IP_BIND_ADDRESS_NO_PORT,
					value: 1,
				},
				{
					level: unix.IPPROTO_IP,
					opt:   unix.IP_FREEBIND,
					value: 1,
				},
			},
			expectedOpts: "..NTF",
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			events := []types.Event{}
			eventCallback := func(event *types.Event) {
				events = append(events, *event)
			}

			runner := utilstest.NewRunnerWithTest(t, nil)

			tracerConfig := &tracer.Config{
				MountnsMap: utilstest.CreateMntNsFilterMap(t, runner.Info.MountNsID),
			}

			createTracer(t, tracerConfig, eventCallback)

			utilstest.RunWithRunner(t, runner, func() error {
				_, err := bindSocketWithOpts("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0, test.opts)
				return err
			})

			// Give some time for the tracer to capture the events
			time.Sleep(100 * time.Millisecond)

			if len(events) != 1 {
				t.Fatalf("Wrong number of events received %d, expected 1", len(events))
			}

			utilstest.Equal(t, test.expectedOpts, events[0].Options,
				"Captured event has wrong options")
		})
	}
}

func TestBindTracerMultipleMntNsIDsFilter(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	events := []types.Event{}
	eventCallback := func(event *types.Event) {
		events = append(events, *event)
	}

	// struct with only fields we want to check on this test
	type expectedEvent struct {
		mntNsID uint64
		port    uint16
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
	}

	createTracer(t, config, eventCallback)

	for i := 0; i < n; i++ {
		utilstest.RunWithRunner(t, runners[i], func() error {
			var err error
			expectedEvents[i].port, err = bindSocket("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0)
			return err
		})
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

		utilstest.Equal(t, expectedEvents[i].port, events[i].Port,
			"Captured event has bad Port")
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

// bindSocketFn returns a function that creates a socket, binds it and
// returns the port the socket was bound to.
func bindSocketFn(ipStr string, domain, typ int, port int) func() (uint16, error) {
	return func() (uint16, error) {
		return bindSocket(ipStr, domain, typ, port)
	}
}

func bindSocket(ipStr string, domain, typ int, port int) (uint16, error) {
	return bindSocketWithOpts(ipStr, domain, typ, port, nil)
}

func bindSocketWithOpts(ipStr string, domain, typ int, port int, opts []sockOpt) (uint16, error) {
	fd, err := unix.Socket(domain, typ, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	for _, opt := range opts {
		if err := unix.SetsockoptInt(fd, opt.level, opt.opt, opt.value); err != nil {
			return 0, fmt.Errorf("SetsockoptInt: %w", err)
		}
	}

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
		return 0, fmt.Errorf("invalid IP address")
	}

	if err := unix.Bind(fd, sa); err != nil {
		return 0, fmt.Errorf("Bind: %w", err)
	}

	sa2, err := unix.Getsockname(fd)
	if err != nil {
		return 0, fmt.Errorf("Getsockname: %w", err)
	}

	if ip.To4() != nil {
		return uint16(sa2.(*unix.SockaddrInet4).Port), nil
	} else if ip.To16() != nil {
		return uint16(sa2.(*unix.SockaddrInet6).Port), nil
	} else {
		return 0, fmt.Errorf("invalid IP address")
	}
}

func bindSocketError() (uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		return 0, fmt.Errorf("Bind: %w", err)
	}

	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err == nil {
		return 0, fmt.Errorf("Bind should have returned error")
	}

	return 0, nil
}
