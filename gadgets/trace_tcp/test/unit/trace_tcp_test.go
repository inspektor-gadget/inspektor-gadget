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

	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
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
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func(t *testing.T, addr string, port int, async bool, expectedErrno syscall.Errno, fdPtr *int, acceptFdPtr *int)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, fd int, acceptFd int, events []ExpectedTraceTcpEvent) error
}

func TestTraceTcpGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"captures_close": {
			ipAddr:        "127.0.0.1",
			port:          9070,
			async:         true, // We only get a close when the connect succeeded or the socket is async. Here we know that the connect should error out
			expectedErrno: syscall.ECONNREFUSED,
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateConnectEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, _ int, events []ExpectedTraceTcpEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					return &ExpectedTraceTcpEvent{
						Proc:    info.Proc,
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
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateConnectEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, _ int, events []ExpectedTraceTcpEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					return &ExpectedTraceTcpEvent{
						Proc:    info.Proc,
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
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateConnectEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, _ int, events []ExpectedTraceTcpEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					return &ExpectedTraceTcpEvent{
						Proc:    info.Proc,
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
			runnerConfig:  &utilstest.RunnerConfig{HostNetwork: true},
			generateEvent: generateAcceptConnectEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, acceptFd int, events []ExpectedTraceTcpEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					return &ExpectedTraceTcpEvent{
						Proc:    info.Proc,
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
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			normalizeEvent := func(event *ExpectedTraceTcpEvent) {
				// Src port varies, so we normalize it
				// TODO: Add a generateEvent function that allows us to test specific src port too.
				if event.Type == "accept" {
					utils.NormalizeInt(&event.Dst.Port)
				} else {
					utils.NormalizeInt(&event.Src.Port)
				}
			}
			fd := -1
			acceptFd := -1

			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
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
