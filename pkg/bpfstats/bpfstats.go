// Copyright 2019-2022 The Inspektor Gadget authors
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

package bpfstats

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type BPFStatsMethod int

const (
	// MethodNone means that no call to EnableBPFStats() has been made or was unsuccessful
	MethodNone BPFStatsMethod = iota

	// MethodBPFFunc uses stats collection via BPF(BPF_ENABLE_STATS)
	MethodBPFFunc

	// MethodSysctl uses stats collection via sysctl (/proc/sys/kernel/bpf_stats_enabled)
	MethodSysctl
)

var (
	mutex     sync.Mutex
	refCnt    int
	statsSock io.Closer
	method    = MethodNone
)

// EnableBPFStats enables collection of bpf program stats. It tries to use BPF_ENABLE_STATS first
// (which requires Linux >= 5.8). If that fails, it will fall back to trying to
// enable via sysctl (/proc/sys/kernel/bpf_stats_enabled). This function will make
// sure that repeated calls will not enable stats collection more than once. Instead,
// it will keep track of the number of calls and only stop stat collection, when
// DisableBPFStats() has been called the same number of times.
func EnableBPFStats() error {
	mutex.Lock()
	defer mutex.Unlock()

	if refCnt != 0 {
		return nil
	}

	// Actually enable
	s, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		// Use fallback method
		err = os.WriteFile(filepath.Join(os.Getenv("HOST_ROOT"), "/proc/sys/kernel/bpf_stats_enabled"), []byte("1"), 0o644)
		if err != nil {
			return fmt.Errorf("enabling stat collection: %w", err)
		}
		method = MethodSysctl
	} else {
		statsSock = s
		method = MethodBPFFunc
	}

	refCnt++

	return nil
}

// DisableBPFStats disables collection of bpf program stats if no consumer
func DisableBPFStats() error {
	mutex.Lock()
	defer mutex.Unlock()

	refCnt--

	if refCnt < 0 {
		refCnt = 0
		return errors.New("bpf stat collection already disabled")
	}

	if refCnt != 0 {
		return nil
	}

	// Actually disable
	switch method {
	case MethodBPFFunc:
		err := statsSock.Close()
		statsSock = nil
		if err != nil {
			return fmt.Errorf("disabling stat collection using BPF(): %w", err)
		}
	case MethodSysctl:
		err := os.WriteFile(filepath.Join(os.Getenv("HOST_ROOT"), "/proc/sys/kernel/bpf_stats_enabled"), []byte("0"), 0o644)
		if err != nil {
			return fmt.Errorf("disabling stat collection using sysctl: %w", err)
		}
	}

	return nil
}

// GetMethod returns the currently used method to enable stats collection. If
// EnableBPFStats() has not yet been called, it will return MethodNone.
func GetMethod() BPFStatsMethod {
	mutex.Lock()
	defer mutex.Unlock()
	return method
}

// GetMapsMemUsage returns a map with the memory usage for all maps on the
// system
func GetMapsMemUsage() (map[ebpf.MapID]uint64, error) {
	var err error
	mapSizes := make(map[ebpf.MapID]uint64)

	curMapID := ebpf.MapID(0)
	nextMapID := ebpf.MapID(0)

	for {
		nextMapID, err = ebpf.MapGetNextID(curMapID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return nil, fmt.Errorf("getting next map ID: %w", err)
		}
		if nextMapID <= curMapID {
			break
		}
		curMapID = nextMapID
		m, err := ebpf.NewMapFromID(curMapID)
		if err != nil {
			continue
		}

		mapSizes[curMapID], err = GetMapMemUsage(m)
		m.Close()
		if err != nil {
			return nil, fmt.Errorf("getting memory usage of map ID (%d): %w", curMapID, err)
		}
	}

	return mapSizes, nil
}

// GetMapMemUsage returns the memory usage of a map
func GetMapMemUsage(m *ebpf.Map) (uint64, error) {
	fdInfoPath := filepath.Join(host.HostProcFs, "self", "fdinfo", fmt.Sprint(m.FD()))
	f, err := os.Open(fdInfoPath)
	if err != nil {
		return 0, fmt.Errorf("reading fdinfo: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "memlock:\t") {
			lineSplit := strings.Split(sc.Text(), "\t")
			if len(lineSplit) == 2 {
				size, err := strconv.ParseUint(lineSplit[1], 10, 64)
				if err != nil {
					return 0, fmt.Errorf("reading memlock: %w", err)
				}
				return size, nil
			}
		}
	}
	return 0, fmt.Errorf("finding memlock in fdinfo")
}
