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

package tracer

import (
	"fmt"
	"net"
	"testing"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSocketTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer, err := NewTracer(types.ALL)
	require.Nil(t, err, "creating tracer: %v", err)

	tracer.CloseIters()
}

type testCase struct {
	name          string
	proto         types.Proto
	addr          string
	port          int
	expectedEvent func(info *utilstest.RunnerInfo, _ any) *types.Event
	socketCreator func(addr string, port int) error
}

func TestSnapshotSocket(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	cases := []testCase{
		{
			name:  "listen_tcp_v4",
			proto: types.TCP,
			addr:  "127.0.0.1",
			port:  8082,
			expectedEvent: func(info *utilstest.RunnerInfo, _ any) *types.Event {
				return &types.Event{
					Event:       eventtypes.Event{Type: eventtypes.NORMAL},
					WithNetNsID: eventtypes.WithNetNsID{NetNsID: info.NetworkNsID},
					Protocol:    "TCP",
					Status:      "LISTEN",
					SrcEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr: "127.0.0.1",
						},
						Port: 8082,
					},
					DstEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							// There is no connection in this test, so there remote address is null.
							Addr: "0.0.0.0",
						},
					},
				}
			},
			socketCreator: func(addr string, port int) error {
				conn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
				if err != nil {
					return fmt.Errorf("listening to %s: %w", addr, err)
				}
				t.Cleanup(func() { conn.Close() })

				return nil
			},
		},
		{
			name:  "listen_udp_v4",
			proto: types.UDP,
			addr:  "127.0.0.1",
			port:  8082,
			expectedEvent: func(info *utilstest.RunnerInfo, _ any) *types.Event {
				return &types.Event{
					Event:       eventtypes.Event{Type: eventtypes.NORMAL},
					WithNetNsID: eventtypes.WithNetNsID{NetNsID: info.NetworkNsID},
					Protocol:    "UDP",
					Status:      "INACTIVE",
					SrcEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr: "127.0.0.1",
						},
						Port: 8082,
					},
					DstEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							// There is no connection in this test, so there remote address is null.
							Addr: "0.0.0.0",
						},
					},
				}
			},
			socketCreator: func(addr string, port int) error {
				conn, err := net.ListenUDP("udp", &net.UDPAddr{
					Port: port,
					IP:   net.ParseIP(addr),
				})
				if err != nil {
					return fmt.Errorf("listening to %s: %w", addr, err)
				}
				t.Cleanup(func() { conn.Close() })

				return nil
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			runner := utilstest.NewRunnerWithTest(t, nil)
			utilstest.RunWithRunner(t, runner, func() error {
				return c.socketCreator(c.addr, c.port)
			})

			tracer, err := NewTracer(c.proto)
			require.ErrorIsf(t, nil, err, "creating tracer: %v", err)
			defer tracer.CloseIters()

			evs, err := tracer.RunCollector(uint32(runner.Info.Tid), "", "", "")
			require.ErrorIsf(t, nil, err, "running collector: %v", err)

			events := make([]types.Event, len(evs))
			for i, ev := range evs {
				events[i] = *ev

				// This is hard to guess the inode number, let's normalize it for the
				// moment.
				events[i].InodeNumber = 0
			}

			utilstest.ExpectAtLeastOneEvent(c.expectedEvent)(t, runner.Info, nil, events)
		})
	}
}
