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

package trace

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event interface {
	any
}

type StandardTracerConfig[E Event] struct {
	// Script name within directory /usr/share/bcc/tools/
	ScriptName string

	// BaseEvent transform a base event eventtypes.Event into the specific
	// tracer's event type. It is needed because EventCallback receives specific
	// tracer's event type.
	BaseEvent func(eventtypes.Event) E

	// EventCallback will be called each time the scripts produces a new line.
	EventCallback func(E)

	// Some gadgets may need to modify the tool's output before marshaling it to
	// avoid changing the BCC tool implementation.
	PrepareLine func(string) string

	// MntnsMap is the mount namespace map for filtering. Notice it is optional.
	MntnsMap *ebpf.Map
}

// StandardTracer is a type used by gadgets that have a BCC Python-based
// implementation. This type in charge of executing the BCC script and calls
// eventCallback each time the scripts produces a new line.
type StandardTracer[E Event] struct {
	eventCallback func(E)
	prepareLine   func(string) string
	baseEvent     func(eventtypes.Event) E

	done              chan bool
	cmd               *exec.Cmd
	mountNsMapPinPath string
}

func NewStandardTracer[E Event](config *StandardTracerConfig[E]) (*StandardTracer[E], error) {
	cmdName := "/usr/share/bcc/tools/" + config.ScriptName
	args := []string{"--json", "--containersmap", "/sys/fs/bpf/gadget/containers"}

	t := &StandardTracer[E]{
		eventCallback: config.EventCallback,
		prepareLine:   config.PrepareLine,
		baseEvent:     config.BaseEvent,
		done:          make(chan bool),
		cmd:           exec.Command(cmdName, args...),
	}

	// Force the stdout and stderr streams to be unbuffered.
	t.cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=TRUE")

	if config.MntnsMap != nil {
		t.mountNsMapPinPath = filepath.Join(gadgets.PinPath, uuid.New().String())
		if err := config.MntnsMap.Pin(t.mountNsMapPinPath); err != nil {
			return nil, err
		}

		t.cmd.Args = append(t.cmd.Args, "--mntnsmap")
		t.cmd.Args = append(t.cmd.Args, t.mountNsMapPinPath)
	}

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

func (t *StandardTracer[E]) stop() error {
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

	if t.mountNsMapPinPath != "" {
		os.Remove(t.mountNsMapPinPath)
	}

	return nil
}

func (t *StandardTracer[E]) Stop() {
	if err := t.stop(); err != nil {
		t.eventCallback(t.baseEvent(eventtypes.Warn(err.Error())))
	}
}

func (t *StandardTracer[E]) run(pipe io.ReadCloser) {
	scanner := bufio.NewScanner(pipe)

	for scanner.Scan() {
		line := scanner.Text()

		if t.prepareLine != nil {
			line = t.prepareLine(line)
		}

		event := t.baseEvent(eventtypes.Event{Type: eventtypes.NORMAL})
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			msg := fmt.Sprintf("failed to unmarshal event '%s': %s", line, err)
			t.eventCallback(t.baseEvent(eventtypes.Warn(msg)))
			return
		}

		t.eventCallback(event)
	}

	t.done <- true
}
