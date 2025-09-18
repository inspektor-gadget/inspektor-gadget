// Copyright 2025 The Inspektor Gadget authors
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
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceBindEvent struct {
	Addr  utils.L4Endpoint `json:"addr"`
	Error string           `json:"error"`
	Proc  utils.Process
}

type testCase struct {
	name    string
	port    uint16
	network string
	version uint8
	addr    string
}

func TestTraceBind(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := []testCase{
		{
			name:    "TCP4 loopback on fixed port",
			addr:    "127.0.0.1",
			network: "TCP",
			version: 4,
			port:    12345,
		},
		{
			name:    "TCP4 loopback on ephemeral port",
			addr:    "127.0.0.1",
			network: "TCP",
			version: 4,
			port:    0,
		},
		{
			name:    "TCP6 loopback on fixed port",
			addr:    "::1",
			network: "TCP",
			port:    2154,
			version: 6,
		},
		{
			name:    "UDP4 loopback on high port",
			addr:    "127.0.0.1",
			network: "UDP",
			port:    12345,
			version: 4,
		},
		{
			name:    "UDP6 loopback on ephemeral port",
			addr:    "::1",
			network: "UDP",
			port:    0,
			version: 6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := utils.NewRunnerWithTest(t, &utils.RunnerConfig{})
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					// pick socket parameters based on tc.network
					var domain, socktype, proto int
					var sa syscall.Sockaddr

					switch tc.network {
					case "TCP":
						socktype, proto = syscall.SOCK_STREAM, syscall.IPPROTO_TCP
					case "UDP":
						socktype, proto = syscall.SOCK_DGRAM, syscall.IPPROTO_UDP
					}

					switch tc.version {
					case 4:
						domain = syscall.AF_INET
						ip := net.ParseIP(tc.addr).To4()
						var ipArray [4]byte
						copy(ipArray[:], ip)
						sa = &syscall.SockaddrInet4{Port: int(tc.port), Addr: ipArray}
					case 6:
						domain = syscall.AF_INET6
						ip := net.ParseIP(tc.addr).To16()
						var ipArray [16]byte
						copy(ipArray[:], ip)
						sa = &syscall.SockaddrInet6{Port: int(tc.port), Addr: ipArray}
					}

					fd, err := syscall.Socket(domain, socktype, proto)
					require.NoError(t, err)
					err = syscall.Bind(fd, sa)

					if tc.port == 0 {
						sockAddr, err := syscall.Getsockname(fd)
						require.NoError(t, err)
						switch s := sockAddr.(type) {
						case *syscall.SockaddrInet4:
							tc.port = uint16(s.Port)
						case *syscall.SockaddrInet6:
							tc.port = uint16(s.Port)
						}
					}

					defer syscall.Close(fd)

					require.NoError(t, err)
					return nil
				})
				return nil
			}

			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceBindEvent]{
				Image:          "trace_bind",
				Timeout:        5 * time.Second,
				MntnsFilterMap: utils.CreateMntNsFilterMap(t, runner.Info.MountNsID),
				OnGadgetRun:    onGadgetRun,
				ParamValues: api.ParamValues{
					"operator.oci.ebpf.ignore-errors": "false",
				},
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
			gadgetRunner.RunGadget()

			utils.ExpectOneEvent(
				func(info *utils.RunnerInfo, fd int) *ExpectedTraceBindEvent {
					return &ExpectedTraceBindEvent{
						Addr: utils.L4Endpoint{
							Addr:    tc.addr,
							Version: tc.version,
							Port:    tc.port,
							Proto:   tc.network,
						},
						Proc:  info.Proc,
						Error: "",
					}
				},
			)(t, runner.Info, 0, gadgetRunner.CapturedEvents)
		})
	}
}
