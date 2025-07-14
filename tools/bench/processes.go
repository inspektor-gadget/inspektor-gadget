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

package main

import (
	"fmt"
	"os/exec"
)

type processesGenerator struct {
	nProcesses int
	processes  []*exec.Cmd
}

func newProcessesGenerator(confStr string) (Generator, error) {
	g := &processesGenerator{
		// TODO: hackly way to get the number of processes to start
		nProcesses: eventsPerSecond,
		processes:  make([]*exec.Cmd, 0, eventsPerSecond),
	}

	return g, nil
}

func (p *processesGenerator) Start() error {
	// Start N "sleep inf" processes
	for i := 0; i < p.nProcesses; i++ {
		cmd := exec.Command("sleep", "inf")

		// Start the process
		if err := cmd.Start(); err != nil {
			// If we fail to start a process, clean up any we've already started
			p.Stop()
			return fmt.Errorf("starting process %d: %w", i, err)
		}

		p.processes = append(p.processes, cmd)
	}

	return nil
}

func (p *processesGenerator) Stop() error {
	// Kill all running processes
	for _, cmd := range p.processes {
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
	}

	return nil
}

func init() {
	registerGenerator("processes", newProcessesGenerator)
}
