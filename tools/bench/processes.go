package main

import (
	"fmt"
	"os/exec"
)

type processesGenerator struct {
	nProcesses int
	processes  []*exec.Cmd
}

func NewProcessesGenerator(confStr string) (Generator, error) {

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
			return fmt.Errorf("failed to start process %d: %w", i, err)
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
	RegisterGenerator("processes", NewProcessesGenerator)
}
