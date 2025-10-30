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
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func TestSocketEnricherCreate(t *testing.T) {
	t.Parallel()

	utils.RequireRoot(t)
	utils.HostInit(t)

	tracer, err := NewSocketEnricher(Config{})
	require.NoError(t, err)
	require.NotNil(t, tracer, "Returned tracer was nil")
}

func TestSocketEnricherStopIdempotent(t *testing.T) {
	t.Parallel()

	utils.RequireRoot(t)
	utils.HostInit(t)

	tracer, err := NewSocketEnricher(Config{})
	require.NoError(t, err)

	// Check that a double stop doesn't cause issues
	tracer.Close()
	tracer.Close()
}

func TestSocketEnricherBadConfig(t *testing.T) {
	t.Parallel()

	utils.RequireRoot(t)
	utils.HostInit(t)

	type testDefinition struct {
		config Config
	}

	for name, test := range map[string]testDefinition{
		"invalid_cwd_size": {
			config: Config{
				Cwd: FieldConfig{
					Enabled: true,
					Size:    3, // Invalid size, must be power of 2
				},
			},
		},
		"cwd_zero_size": {
			config: Config{
				Cwd: FieldConfig{
					Enabled: true,
					Size:    0, // Invalid size, must be power of 2 and greater than 0
				},
			},
		},
		"invalid_exepath_size": {
			config: Config{
				Exepath: FieldConfig{
					Enabled: true,
					Size:    3, // Invalid size, must be power of 2
				},
			},
		},
		"too_big_cwd_size": {
			config: Config{
				Cwd: FieldConfig{
					Enabled: true,
					Size:    4096 * 2, // Too big, max is 4096
				},
			},
		},
		"too_big_exepath_size": {
			config: Config{
				Exepath: FieldConfig{
					Enabled: true,
					Size:    4096 * 2, // Too big, max is 4096
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := NewSocketEnricher(test.config)
			require.Error(t, err)
		})
	}
}

type sockOpt struct {
	level int
	opt   int
	value int
}

type socketEnricherMapEntry struct {
	Key   socketenricherGadgetSocketKey
	Value socketenricherGadgetSocketValue
}

func TestSocketEnricherBind(t *testing.T) {
	t.Parallel()

	utils.RequireRoot(t)
	utils.HostInit(t)

	cwd, err := os.Getwd()
	require.NoError(t, err, "Cannot get current working directory")
	exepath, err := os.Readlink("/proc/self/exe")
	require.NoError(t, err, "Cannot get current executable path")
	ptask := host.GetProcComm(os.Getppid())

	type testDefinition struct {
		runnerConfig  *utils.RunnerConfig
		generateEvent func() (uint16, int, error)
		expectedEvent func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry
	}

	// Golang generics cannot parameterize array sizes
	// https://github.com/golang/go/issues/44253
	stringToSlice := func(s string) (ret [16]int8) {
		for i := 0; i < 16; i++ {
			if i >= len(s) {
				break
			}
			ret[i] = int8(s[i])
		}
		return
	}
	stringToSlice4096 := func(s string) (ret [4096]int8) {
		for i := 0; i < 4096; i++ {
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
			expectedEvent: func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherGadgetSocketKey{
						Netns:  uint32(info.NetworkNsID),
						Family: unix.AF_INET,
						Proto:  unix.IPPROTO_UDP,
						Port:   port,
					},
					Value: socketenricherGadgetSocketValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Ppid:    uint32(os.Getppid()),
						Ptid:    uint32(os.Getppid()),
						Task:    stringToSlice("socketenricher."),
						Ptask:   stringToSlice(ptask),
						Cwd:     stringToSlice4096(cwd),
						Exepath: stringToSlice4096(exepath),
					},
				}
			},
		},
		"udp6": {
			generateEvent: bindSocketFn("::", unix.AF_INET6, unix.SOCK_DGRAM, 0),
			expectedEvent: func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherGadgetSocketKey{
						Netns:  uint32(info.NetworkNsID),
						Family: unix.AF_INET6,
						Proto:  unix.IPPROTO_UDP,
						Port:   port,
					},
					Value: socketenricherGadgetSocketValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Ppid:    uint32(os.Getppid()),
						Ptid:    uint32(os.Getppid()),
						Task:    stringToSlice("socketenricher."),
						Ptask:   stringToSlice(ptask),
						Cwd:     stringToSlice4096(cwd),
						Exepath: stringToSlice4096(exepath),
					},
				}
			},
		},
		"udp6-only": {
			generateEvent: func() (uint16, int, error) {
				opts := []sockOpt{
					{unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1},
				}
				return bindSocketWithOpts("::", unix.AF_INET6, unix.SOCK_DGRAM, 0, opts)
			},
			expectedEvent: func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherGadgetSocketKey{
						Netns:  uint32(info.NetworkNsID),
						Family: unix.AF_INET6,
						Proto:  unix.IPPROTO_UDP,
						Port:   port,
					},
					Value: socketenricherGadgetSocketValue{
						Mntns:    info.MountNsID,
						PidTgid:  uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Ppid:     uint32(os.Getppid()),
						Ptid:     uint32(os.Getppid()),
						Task:     stringToSlice("socketenricher."),
						Ptask:    stringToSlice(ptask),
						Ipv6only: int8(1),
						Cwd:      stringToSlice4096(cwd),
						Exepath:  stringToSlice4096(exepath),
					},
				}
			},
		},
		"tcp": {
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			expectedEvent: func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherGadgetSocketKey{
						Netns:  uint32(info.NetworkNsID),
						Family: unix.AF_INET,
						Proto:  unix.IPPROTO_TCP,
						Port:   port,
					},
					Value: socketenricherGadgetSocketValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Ppid:    uint32(os.Getppid()),
						Ptid:    uint32(os.Getppid()),
						Task:    stringToSlice("socketenricher."),
						Ptask:   stringToSlice(ptask),
						Cwd:     stringToSlice4096(cwd),
						Exepath: stringToSlice4096(exepath),
					},
				}
			},
		},
		"tcp6": {
			generateEvent: bindSocketFn("::", unix.AF_INET6, unix.SOCK_STREAM, 0),
			expectedEvent: func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherGadgetSocketKey{
						Netns:  uint32(info.NetworkNsID),
						Family: unix.AF_INET6,
						Proto:  unix.IPPROTO_TCP,
						Port:   port,
					},
					Value: socketenricherGadgetSocketValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Ppid:    uint32(os.Getppid()),
						Ptid:    uint32(os.Getppid()),
						Task:    stringToSlice("socketenricher."),
						Ptask:   stringToSlice(ptask),
						Cwd:     stringToSlice4096(cwd),
						Exepath: stringToSlice4096(exepath),
					},
				}
			},
		},
		"tcp6-only": {
			generateEvent: func() (uint16, int, error) {
				opts := []sockOpt{
					{unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1},
				}
				return bindSocketWithOpts("::", unix.AF_INET6, unix.SOCK_STREAM, 0, opts)
			},
			expectedEvent: func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherGadgetSocketKey{
						Netns:  uint32(info.NetworkNsID),
						Family: unix.AF_INET6,
						Proto:  unix.IPPROTO_TCP,
						Port:   port,
					},
					Value: socketenricherGadgetSocketValue{
						Mntns:    info.MountNsID,
						PidTgid:  uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Ppid:     uint32(os.Getppid()),
						Ptid:     uint32(os.Getppid()),
						Task:     stringToSlice("socketenricher."),
						Ptask:    stringToSlice(ptask),
						Ipv6only: int8(1),
						Cwd:      stringToSlice4096(cwd),
						Exepath:  stringToSlice4096(exepath),
					},
				}
			},
		},
		"tcp_uid_gid": {
			runnerConfig:  &utils.RunnerConfig{Uid: 1000, Gid: 1111},
			generateEvent: bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 0),
			expectedEvent: func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry {
				return &socketEnricherMapEntry{
					Key: socketenricherGadgetSocketKey{
						Netns:  uint32(info.NetworkNsID),
						Family: unix.AF_INET,
						Proto:  unix.IPPROTO_TCP,
						Port:   port,
					},
					Value: socketenricherGadgetSocketValue{
						Mntns:   info.MountNsID,
						PidTgid: uint64(uint32(info.Pid))<<32 + uint64(info.Tid),
						Ppid:    uint32(os.Getppid()),
						Ptid:    uint32(os.Getppid()),
						UidGid:  uint64(1111)<<32 + uint64(1000),
						Task:    stringToSlice("socketenricher."),
						Ptask:   stringToSlice(ptask),
						Cwd:     stringToSlice4096(cwd),
						Exepath: stringToSlice4096(exepath),
					},
				}
			},
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			seConfig := Config{
				Cwd: FieldConfig{
					Enabled: true,
					Size:    4096,
				},
				Exepath: FieldConfig{
					Enabled: true,
					Size:    4096,
				},
			}
			runner := utils.NewRunnerWithTest(t, test.runnerConfig)

			// We will test 2 scenarios with 2 different tracers:
			// 1. earlyTracer will be started before the event is generated
			// 2. lateTracer will be started after the event is generated
			earlyTracer, err := NewSocketEnricher(seConfig)
			require.NoError(t, err)
			t.Cleanup(earlyTracer.Close)

			// Generate the event in the fake container
			var port uint16
			var fd int
			utils.RunWithRunner(t, runner, func() error {
				var err error
				port, fd, err = test.generateEvent()
				t.Cleanup(func() {
					// cleanup only if it has not been already closed
					if fd != -1 {
						unix.Close(fd)
					}
				})
				return err
			})

			// Start the late tracer after the event has been generated
			lateTracer, err := NewSocketEnricher(seConfig)
			require.NoError(t, err)
			t.Cleanup(lateTracer.Close)

			earlyNormalize := func(entry *socketEnricherMapEntry) {
				entry.Value.Sock = 0
			}
			lateNormalize := func(entry *socketEnricherMapEntry) {
				earlyNormalize(entry)

				// Remove tid: the late tracer cannot distinguish between threads
				entry.Value.PidTgid = 0xffffffff00000000 & entry.Value.PidTgid

				// Our fake container is just a thread in a different MountNsID
				// But the late tracer cannot distinguish threads.
				if entry.Value.Mntns > 0 {
					entry.Value.Mntns = 1
				}

				// We're not able to test uid and gid in the late tracer because our
				// fake container is just another thread running on the same process
				// and that tracer cannot distinguish threads.
				entry.Value.UidGid = 0
			}

			t.Logf("Testing if early tracer noticed the event")
			entries := socketsMapEntries(t, earlyTracer, earlyNormalize, nil)
			utils.ExpectAtLeastOneEvent(test.expectedEvent)(t, runner.Info, port, entries)

			t.Logf("Testing if late tracer noticed the event")
			entries2 := socketsMapEntries(t, lateTracer, lateNormalize, nil)
			expectedEvent2 := func(info *utils.RunnerInfo, port uint16) *socketEnricherMapEntry {
				e := test.expectedEvent(info, port)
				lateNormalize(e)
				return e
			}
			utils.ExpectAtLeastOneEvent(expectedEvent2)(t, runner.Info, port, entries2)

			t.Logf("Close socket in order to check for cleanup")
			if fd != -1 {
				unix.Close(fd)
				// Disable t.Cleanup() above
				fd = -1
			}

			filter := func(e *socketEnricherMapEntry) bool {
				expected := test.expectedEvent(runner.Info, port)
				return !reflect.DeepEqual(expected, e)
			}

			t.Logf("Testing if entry is cleaned properly in early tracer")
			entries = socketsMapEntries(t, earlyTracer, earlyNormalize, filter)
			require.Len(t, entries, 0, "Entry not cleaned properly: %+v", entries)

			t.Logf("Testing if entry is cleaned properly in late tracer")
			entries2 = socketsMapEntries(t, lateTracer, lateNormalize, filter)
			require.Len(t, entries2, 0, "Entry for late tracer not cleaned properly: %+v", entries2)
		})
	}
}

func socketsMapEntries(
	t *testing.T,
	tracer *SocketEnricher,
	normalize func(entry *socketEnricherMapEntry),
	filter func(*socketEnricherMapEntry) bool,
) (entries []socketEnricherMapEntry) {
	iter := tracer.SocketsMap().Iterate()
	var key socketenricherGadgetSocketKey
	var value socketenricherGadgetSocketValue
	for iter.Next(&key, &value) {
		entry := socketEnricherMapEntry{
			Key:   key,
			Value: value,
		}

		normalize(&entry)

		if filter != nil && filter(&entry) {
			continue
		}
		entries = append(entries, entry)
	}
	require.NoError(t, iter.Err(), "Cannot iterate over socket enricher map")
	return entries
}

// bindSocketFn returns a function that creates a socket, binds it and
// returns the port the socket was bound to.
func bindSocketFn(ipStr string, domain, typ int, port int) func() (uint16, int, error) {
	return func() (uint16, int, error) {
		return bindSocket(ipStr, domain, typ, port)
	}
}

func bindSocket(ipStr string, domain, typ int, port int) (uint16, int, error) {
	return bindSocketWithOpts(ipStr, domain, typ, port, nil)
}

func setProcessName(name string) error {
	bytes := append([]byte(name), 0)
	return unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&bytes[0])), 0, 0, 0)
}

func bindSocketWithOpts(ipStr string, domain, typ int, port int, opts []sockOpt) (uint16, int, error) {
	// The process name is usually based on the package name
	// ("socketenricher.") but it could be changed (e.g. running tests in the
	// Goland IDE environment). Make sure the tests work regardless of the
	// environment.
	//
	// Example how to test this:
	//
	//	$ go test -c ./pkg/socketenricher/...
	//	$ sudo ./socketenricher.test
	//	PASS
	//	$ mv socketenricher.test se.test
	//	$ sudo ./se.test
	//	FAIL
	err := setProcessName("socketenricher.")
	if err != nil {
		return 0, -1, fmt.Errorf("setProcessName: %w", err)
	}

	fd, err := unix.Socket(domain, typ, 0)
	if err != nil {
		return 0, -1, err
	}

	for _, opt := range opts {
		if err := unix.SetsockoptInt(fd, opt.level, opt.opt, opt.value); err != nil {
			return 0, -1, fmt.Errorf("SetsockoptInt: %w", err)
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
		return 0, -1, fmt.Errorf("invalid IP address")
	}

	if err := unix.Bind(fd, sa); err != nil {
		return 0, -1, fmt.Errorf("Bind: %w", err)
	}

	sa2, err := unix.Getsockname(fd)
	if err != nil {
		return 0, fd, fmt.Errorf("Getsockname: %w", err)
	}

	if ip.To4() != nil {
		return uint16(sa2.(*unix.SockaddrInet4).Port), fd, nil
	} else if ip.To16() != nil {
		return uint16(sa2.(*unix.SockaddrInet6).Port), fd, nil
	} else {
		return 0, fd, fmt.Errorf("invalid IP address")
	}
}
