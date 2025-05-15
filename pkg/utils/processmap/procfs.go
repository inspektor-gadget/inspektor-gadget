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

package processmap

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/processmap/types"
)

// getProgIDFromFile reads a file and extracts the prog_id from it.
// The file has a format like:
// pos:    0
// flags:  02000000
// mnt_id: 16
// ino:    61
// link_type:      perf
// link_id:        1016
// prog_tag:       f1795a781ee952cc
// prog_id:        188
func getProgIDFromFile(fn string) (uint32, error) {
	f, err := os.Open(fn)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		after, ok := strings.CutPrefix(line, "prog_id:")
		if !ok {
			continue
		}
		progID, err := strconv.ParseUint(strings.TrimSpace(after), 10, 32)
		if err != nil {
			return 0, err
		}
		if progID > math.MaxInt32 {
			return 0, fmt.Errorf("progID (%d) exceeds math.MaxInt32 (%d)", progID, math.MaxInt32)
		}
		return uint32(progID), nil
	}
	return 0, os.ErrNotExist
}

func fetchPidMapFromProcFs() (map[uint32][]types.Process, error) {
	processes, err := os.ReadDir(host.HostProcFs)
	if err != nil {
		return nil, err
	}
	pidmap := make(map[uint32][]types.Process)
	for _, p := range processes {
		if !p.IsDir() {
			continue
		}
		_, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fdescs, err := os.ReadDir(filepath.Join(host.HostProcFs, p.Name(), "fdinfo"))
		if err != nil {
			continue
		}
		for _, fd := range fdescs {
			progID, err := getProgIDFromFile(filepath.Join(host.HostProcFs, p.Name(), "fdinfo", fd.Name()))
			if err != nil {
				continue
			}

			pid, err := strconv.ParseUint(p.Name(), 10, 32)
			if err != nil {
				return nil, err
			}
			if pid > math.MaxInt32 {
				return nil, fmt.Errorf("PID (%d) exceeds math.MaxInt32 (%d)", pid, math.MaxInt32)
			}
			process := types.Process{
				Pid:  uint32(pid),
				Comm: strings.TrimSpace(string(host.GetProcComm(int(pid)))),
			}
			if slices.Contains(pidmap[progID], process) {
				continue
			}
			pidmap[progID] = append(pidmap[progID], process)
		}
	}
	return pidmap, nil
}
