//go:build linux
// +build linux

// Copyright 2023 The Inspektor Gadget authors
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

package socketenricher

import (
	"fmt"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
)

func TestSocketEnricherCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer, err := NewSocketEnricher()
	if err != nil {
		t.Fatal(err)
	}
	if tracer == nil {
		t.Fatal("Returned tracer was nil")
	}
}

func TestSocketEnricherStopIdempotent(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer, _ := NewSocketEnricher()

	// Check that a double stop doesn't cause issues
	tracer.Close()
	tracer.Close()
}

type sockOpt struct {
	level int
	opt   int
	value int
}

func TestSocketEnricherBind(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	type socketEnricherMapEntry struct {
		Key   socketenricherSocketsKey
		Value socketenricherSocketsValue
	}

	type testDefinition struct {
		generateEvent func() (uint16, error)
		validateEvent func(t *testing.T, info *utilstest.RunnerInfo, port uint16, entries []socketEnricherMapEntry)
	}

	netns, err := containerutils.GetNetNs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}

	stringToSlice := func(s string) (ret [16]int8) {
		for i := 0; i < 16; i++ {
			if i >= len(s) {
				break
			}
			ret[i] = int8(s[i])
		}
		return
	}

	for name, test := range map[string]testDefinition{
		"udp": {
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_DGRAM, 0),
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherSocketsKey{
						Netns:  uint32(netns),
						Family: unix.AF_INET,
						Proto:  unix.IPPROTO_UDP,
						Port:   port,
					},
					Value: socketenricherSocketsValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Task:    stringToSlice("socketenricher."),
					},
				}
			}),
		},
		"udp6": {
			generateEvent: bindSocketFn("::", unix.AF_INET6, unix.SOCK_DGRAM, 0),
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherSocketsKey{
						Netns:  uint32(netns),
						Family: unix.AF_INET6,
						Proto:  unix.IPPROTO_UDP,
						Port:   port,
					},
					Value: socketenricherSocketsValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Task:    stringToSlice("socketenricher."),
					},
				}
			}),
		},
		"tcp": {
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherSocketsKey{
						Netns:  uint32(netns),
						Family: unix.AF_INET,
						Proto:  unix.IPPROTO_TCP,
						Port:   port,
					},
					Value: socketenricherSocketsValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Task:    stringToSlice("socketenricher."),
					},
				}
			}),
		},
		"tcp6": {
			generateEvent: bindSocketFn("::", unix.AF_INET6, unix.SOCK_STREAM, 0),
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherSocketsKey{
						Netns:  uint32(netns),
						Family: unix.AF_INET6,
						Proto:  unix.IPPROTO_TCP,
						Port:   port,
					},
					Value: socketenricherSocketsValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Task:    stringToSlice("socketenricher."),
					},
				}
			}),
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runner := utilstest.NewRunnerWithTest(t, nil)

			tracer, err := NewSocketEnricher()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(tracer.Close)

			var port uint16

			utilstest.RunWithRunner(t, runner, func() error {
				var err error
				port, err = test.generateEvent()
				return err
			})

			iter := tracer.SocketsMap().Iterate()
			var key socketenricherSocketsKey
			var value socketenricherSocketsValue
			var entries []socketEnricherMapEntry
			for iter.Next(&key, &value) {
				entries = append(entries, socketEnricherMapEntry{
					Key:   key,
					Value: value,
				})
			}
			if err := iter.Err(); err != nil {
				t.Fatal("Cannot iterate over socket enricher map:", err)
			}

			if test.validateEvent != nil {
				test.validateEvent(t, runner.Info, port, entries)
			}
		})
	}
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
