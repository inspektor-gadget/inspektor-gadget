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

package gadgets

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// StandardTracerBase is a type used by gadgets that have a BCC
// Python-based implementation. This type in on charge of executing the
// BCC script and calls lineCallback each time the scripts produces a
// new line.
type StandardTracerBase struct {
	lineCallback func(string)
	done         chan bool
	cmd          *exec.Cmd
}

func NewStandardTracer(lineCallback func(string), name string, args ...string) (*StandardTracerBase, error) {
	t := &StandardTracerBase{
		lineCallback: lineCallback,
		done:         make(chan bool),
		cmd:          exec.Command(name, args...),
	}

	// Force the stdout and stderr streams to be unbuffered.
	t.cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=TRUE")

	pipe, err := t.cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error getting pipe: %w", err)
	}

	if err := t.cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	go t.run(pipe)

	return t, nil
}

func (t *StandardTracerBase) Stop() error {
	if err := t.cmd.Process.Signal(syscall.SIGINT); err != nil {
		return fmt.Errorf("failed to interrupt gadget process: %w", err)
	}

	timer := time.NewTimer(2 * time.Second)

	select {
	case <-timer.C:
		return fmt.Errorf("gadget didn't finish within timeout")
	case <-t.done:
	}

	if err := t.cmd.Wait(); err != nil {
		return fmt.Errorf("failed to wait for gadget process: %w", err)
	}

	return nil
}

func (t *StandardTracerBase) run(pipe io.ReadCloser) {
	scanner := bufio.NewScanner(pipe)

	for scanner.Scan() {
		line := scanner.Text()
		t.lineCallback(line)
	}

	t.done <- true
}
