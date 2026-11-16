// Copyright 2024 The Inspektor Gadget authors
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

package tests

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceTcpEvent struct {
	Proc utils.Process `json:"proc"`

	Type     string           `json:"type"`
	NetNsId  int              `json:"netns_id"`
	Src      utils.L4Endpoint `json:"src"`
	Dst      utils.L4Endpoint `json:"dst"`
	Error    string           `json:"error"`
	Fd       int              `json:"fd"`
	AcceptFd int              `json:"accept_fd"`
}

type testDef struct {
	ipAddr        string
	port          int
	async         bool
	expectedErrno syscall.Errno // This is the expected errno from rawDial and not from any events captured by the gadget
	runnerConfig  *utils.RunnerConfig
	generateEvent func(t *testing.T, addr string, port int, async bool, expectedErrno syscall.Errno, fdPtr *int, acceptFdPtr *int)
	validateEvent func(t *testing.T, info *utils.RunnerInfo, fd int, acceptFd int, events []ExpectedTraceTcpEvent) error
}

func TestTraceTcpGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"captures_close": {
			ipAddr:        "127.0.0.1",
			port:          9070,
			async:         true, // We only get a close when the connect succeeded or the socket is async. Here we know that the connect should error out
			expectedErrno: syscall.ECONNREFUSED,
			runnerConfig:  &utils.RunnerConfig{},
			generateEvent: generateConnectEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, fd int, _ int, events []ExpectedTraceTcpEvent) error {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceTcpEvent{
						Proc:    proc,
						Type:    "close",
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   "TCP",
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9070,
							Proto:   "TCP",
						},
						Error:    "",
						Fd:       -1,
						AcceptFd: -1,
					}
				})(t, info, fd, events)
				return nil
			},
		},
		"captures_connect_sync_err": {
			ipAddr:        "127.0.0.1",
			port:          9070,
			async:         false,
			expectedErrno: syscall.ECONNREFUSED,
			runnerConfig:  &utils.RunnerConfig{},
			generateEvent: generateConnectEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, fd int, _ int, events []ExpectedTraceTcpEvent) error {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceTcpEvent{
						Proc:    proc,
						Type:    "connect",
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   "TCP",
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9070,
							Proto:   "TCP",
						},
						Error:    "ECONNREFUSED",
						Fd:       fd,
						AcceptFd: -1,
					}
				})(t, info, fd, events)
				return nil
			},
		},
		"captures_connect_async_err": {
			ipAddr:        "127.0.0.1",
			port:          9070,
			async:         true,
			expectedErrno: syscall.ECONNREFUSED,
			runnerConfig:  &utils.RunnerConfig{},
			generateEvent: generateConnectEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, fd int, _ int, events []ExpectedTraceTcpEvent) error {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceTcpEvent{
						Proc:    proc,
						Type:    "connect",
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   "TCP",
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9070,
							Proto:   "TCP",
						},
						Error:    "ECONNREFUSED",
						Fd:       fd,
						AcceptFd: -1,
					}
				})(t, info, fd, events)
				return nil
			},
		},
		"captures_accept": {
			ipAddr:        "127.0.0.1",
			port:          9071,
			runnerConfig:  &utils.RunnerConfig{HostNetwork: true},
			generateEvent: generateAcceptConnectEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, fd int, acceptFd int, events []ExpectedTraceTcpEvent) error {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceTcpEvent{
						Proc:    proc,
						Type:    "accept",
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9071,
							Proto:   "TCP",
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   "TCP",
						},
						Fd:       fd,
						AcceptFd: acceptFd,
					}
				})(t, info, fd, events)
				return nil
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := utils.NewRunnerWithTest(t, testCase.runnerConfig)
			normalizeEvent := func(event *ExpectedTraceTcpEvent) {
				// Src port varies, so we normalize it
				// TODO: Add a generateEvent function that allows us to test specific src port too.
				if event.Type == "accept" {
					utils.NormalizeInt(&event.Dst.Port)
				} else {
					utils.NormalizeInt(&event.Src.Port)
				}
				utils.NormalizeParentTid(&event.Proc)
			}
			fd := -1
			acceptFd := -1

			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					testCase.generateEvent(t, testCase.ipAddr, testCase.port, testCase.async, testCase.expectedErrno, &fd, &acceptFd)
					return nil
				})
				return nil
			}

			Opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceTcpEvent]{
				Image:          "trace_tcp",
				Timeout:        5 * time.Second,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, Opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, fd, acceptFd, gadgetRunner.CapturedEvents)
		})
	}
}

// TestTraceTcpGadgetV4MappedConnectsDoNotLeak checks that connects from an
// AF_INET6 socket to an IPv4-mapped address don't leave stale entries in the
// gadget's internal map. If they did, the map would fill up and new connects
// would stop being reported.
func TestTraceTcpGadgetV4MappedConnectsDoNotLeak(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	const (
		port = 9072
		// Must be bigger than MAX_ENTRIES in gadgets/trace_tcp/ebpf/common.h
		v4MappedConnects = 8192 + 512
		// Different from the address used to fill the map: connects to an
		// already leaked tuple would be reported even with a full map.
		newDstAddr = "127.0.0.2"
	)

	runner := utils.NewRunnerWithTest(t, &utils.RunnerConfig{})

	var genErr error
	onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
		utils.RunWithRunner(t, runner, func() error {
			genErr = generateV4MappedConnects(port, v4MappedConnects, newDstAddr)
			return nil
		})
		return nil
	}

	gadgetRunner := gadgetrunner.NewGadgetRunner(t, gadgetrunner.GadgetRunnerOpts[ExpectedTraceTcpEvent]{
		Image:       "trace_tcp",
		Timeout:     20 * time.Second,
		OnGadgetRun: onGadgetRun,
	})

	gadgetRunner.RunGadget()

	if errors.Is(genErr, unix.EAFNOSUPPORT) {
		t.Skip("IPv6 is not supported on this system")
	}
	require.NoError(t, genErr)

	for _, event := range gadgetRunner.CapturedEvents {
		if event.Type == "connect" && event.Dst.Addr == newDstAddr && event.Dst.Port == port {
			return
		}
	}
	t.Fatalf("connect to %s:%d wasn't captured after %d IPv4-mapped connects", newDstAddr, port, v4MappedConnects)
}

// generateV4MappedConnects does n connects from an AF_INET6 socket to
// ::ffff:127.0.0.1 and then one connect from an AF_INET socket to newDstAddr.
func generateV4MappedConnects(port, n int, newDstAddr string) error {
	lfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("creating listener socket: %w", err)
	}

	if err := unix.SetsockoptInt(lfd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(lfd)
		return fmt.Errorf("setting SO_REUSEADDR: %w", err)
	}
	// Listen on all the addresses, so 127.0.0.1 and newDstAddr both work
	if err := unix.Bind(lfd, &unix.SockaddrInet4{Port: port}); err != nil {
		unix.Close(lfd)
		return fmt.Errorf("binding listener: %w", err)
	}
	if err := unix.Listen(lfd, 1024); err != nil {
		unix.Close(lfd)
		return fmt.Errorf("listening: %w", err)
	}

	// Accept and close every connection, so the accept queue never fills up.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			fd, _, err := unix.Accept(lfd)
			if err != nil {
				return
			}
			unix.Close(fd)
		}
	}()
	defer func() {
		// Shutdown wakes up the blocked accept, close alone doesn't
		unix.Shutdown(lfd, unix.SHUT_RDWR)
		<-acceptDone
		unix.Close(lfd)
	}()

	mapped := &unix.SockaddrInet6{
		Port: port,
		Addr: [16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1}, // ::ffff:127.0.0.1
	}
	for i := 0; i < n; i++ {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
		if err != nil {
			return fmt.Errorf("creating AF_INET6 socket: %w", err)
		}
		err = unix.Connect(fd, mapped)
		unix.Close(fd)
		if err != nil {
			return fmt.Errorf("connecting to ::ffff:127.0.0.1: %w", err)
		}
	}

	// Give userspace some time to consume the events generated above
	time.Sleep(500 * time.Millisecond)

	ip := net.ParseIP(newDstAddr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address: %s", newDstAddr)
	}
	if err := rawDial([4]byte(ip), port, false, nil); err != nil {
		return fmt.Errorf("connecting to %s: %w", newDstAddr, err)
	}
	return nil
}

func generateConnectEvent(t *testing.T, ipAddr string, port int, async bool, expectedErrno syscall.Errno, fdPtr *int, _ *int) {
	// Split ipAddr into a 4 bytes array
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		t.Logf("Invalid IPv4 address: %s", ipAddr)
		return
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		t.Logf("Invalid IPv4 address: %s", ipAddr)
		return
	}

	err := rawDial([4]byte(ipv4), port, async, fdPtr)
	if err != nil && !errors.Is(err, expectedErrno) {
		t.Logf("Failed to dial: %v", err)
		return
	}
}

func rawDial(ipv4 [4]byte, port int, async bool, fdPtr *int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("Failed to create socket: %w", err)
	}
	defer unix.Close(fd)
	if fdPtr != nil {
		*fdPtr = fd
	}

	addr := &unix.SockaddrInet4{
		Port: port,
		Addr: ipv4,
	}

	if !async {
		return unix.Connect(fd, addr)
	}

	// Set the socket to non-blocking
	flags, err := unix.FcntlInt(uintptr(fd), syscall.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("Failed to get flags: %w", err)
	}
	flags |= syscall.O_NONBLOCK
	_, err = unix.FcntlInt(uintptr(fd), syscall.F_SETFL, flags)
	if err != nil {
		return fmt.Errorf("Failed to set flags: %w", err)
	}

	// Initiate the connect
	err = unix.Connect(fd, addr)
	if err != nil && !errors.Is(err, syscall.EINPROGRESS) {
		return err
	}

	// Wait for the async connect to finish
	_, err = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, int((1 * time.Second).Nanoseconds()))
	if err != nil {
		return fmt.Errorf("Failed to poll: %w", err)
	}

	// Check the error
	sockErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return fmt.Errorf("Failed to getsockopt: %w", err)
	}
	if sockErr != 0 {
		return syscall.Errno(sockErr)
	}
	return nil
}

func generateAcceptConnectEvent(t *testing.T, _ string, port int, _ bool, expectedErrno syscall.Errno, fdPtr *int, acceptFdPtr *int) {
	err := rawAcceptConnect(port, fdPtr, acceptFdPtr)
	if err != nil && !errors.Is(err, expectedErrno) {
		t.Logf("Failed to accept: %v", err)
		return
	}
}

func rawAcceptConnect(port int, fdPtr *int, acceptFdPtr *int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("Failed to create socket: %w", err)
	}
	defer unix.Close(fd)
	if fdPtr != nil {
		*fdPtr = fd
	}

	addr := &unix.SockaddrInet4{
		Port: port,
		Addr: [4]byte{127, 0, 0, 1},
	}

	// Set socket options to allow address reuse
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err != nil {
		return fmt.Errorf("Failed to set socket options: %w", err)
	}

	err = unix.Bind(fd, addr)
	if err != nil {
		return fmt.Errorf("Failed to bind: %w", err)
	}

	err = unix.Listen(fd, 10)
	if err != nil {
		return fmt.Errorf("Failed to listen: %w", err)
	}

	go rawDial([4]byte{127, 0, 0, 1}, port, false, nil)
	time.Sleep(200 * time.Millisecond)

	acceptFd, _, err := unix.Accept(fd)
	if err != nil {
		return fmt.Errorf("Failed to accept: %w", err)
	}
	if acceptFdPtr != nil {
		*acceptFdPtr = acceptFd
	}

	return nil
}
