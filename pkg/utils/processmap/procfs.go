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
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func getProgIDFromFile(fn string) (uint32, error) {
	f, err := os.Open(fn)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "prog_id:") {
			progID, _ := strconv.ParseUint(strings.TrimSpace(strings.Split(sc.Text(), ":")[1]), 10, 32)
			return uint32(progID), nil
		}
	}
	return 0, os.ErrNotExist
}

func getPidMapFromProcFs() (map[uint32][]Process, error) {
	processes, err := os.ReadDir(host.HostProcFs)
	if err != nil {
		return nil, err
	}
	pidmap := make(map[uint32][]Process)
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
			if progID, err := getProgIDFromFile(filepath.Join(host.HostProcFs, p.Name(), "fdinfo", fd.Name())); err == nil {
				pid, err := strconv.ParseUint(p.Name(), 10, 32)
				if err != nil {
					return nil, err
				}
				if pid > math.MaxInt32 {
					return nil, fmt.Errorf("PID (%d) exceeds math.MaxInt32 (%d)", pid, math.MaxInt32)
				}
				if _, ok := pidmap[progID]; !ok {
					pidmap[progID] = make([]Process, 0, 1)
				}
				comm := host.GetProcComm(int(pid))
				pidmap[progID] = append(pidmap[progID], Process{
					Pid:  uint32(pid),
					Comm: strings.TrimSpace(string(comm)),
				})
			}
		}
	}
	return pidmap, nil
}
