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

import "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/processmap/types"

type ProcessMap struct {
	bpfIter             *pidIterEbpf
	useFallbackIterator bool
}

func NewProcessMap() (*ProcessMap, error) {
	// To resolve pids, we will first try to iterate using a bpf
	// program. If that doesn't work, we will fall back to scanning
	// all used fds in all processes /proc/$pid/fdinfo/$fd.
	bpfIter, err := NewTracer()
	if err != nil {
		return &ProcessMap{
			useFallbackIterator: true,
		}, nil
	}

	return &ProcessMap{
		bpfIter:             bpfIter,
		useFallbackIterator: false,
	}, nil
}

// Fetch returns a map containing processes using eBPF programs.
// The map key is the program ID, and the value is a slice of Process structs
// containing the PID and command name of the processes using that program.
func (p *ProcessMap) Fetch() (map[uint32][]types.Process, error) {
	if p.useFallbackIterator {
		return fetchPidMapFromProcFs()
	}

	return p.bpfIter.fetch()
}

func (p *ProcessMap) Close() {
	if p.bpfIter != nil {
		p.bpfIter.Close()
	}
}
