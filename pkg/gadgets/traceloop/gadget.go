// Copyright 2019-2021 The Inspektor Gadget authors
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

package traceloop

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
)

type Trace struct {
	started bool
	cmd     *exec.Cmd
}

type TraceFactory struct {
	gadgets.BaseFactory
	// Indicates if there is any running instance in this node
	started bool
	mu      sync.Mutex
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	return `The traceloop gadget traces system calls in a similar way to strace but with
some differences:

* traceloop uses BPF instead of ptrace
* traceloop's tracing granularity is the container instead of a process
* traceloop's traces are recorded in a fast, in-memory, overwritable ring
  buffer like a flight recorder. The tracing could be permanently enabled and
  inspected in case of crash.
`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"ExternalResource": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	trace.stop()
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{}
	}

	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start traceloop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				t := f.LookupOrCreate(name, n).(*Trace)
				if t.started {
					trace.Status.State = "Started"
					return
				}

				f.mu.Lock()
				defer f.mu.Unlock()

				if f.started {
					trace.Status.OperationError = "There is already one traceloop instance running on this node. Please stop it first."
					return
				}

				t.Start(trace)
				f.started = t.started
			},
		},
		"stop": {
			Doc: "Stop traceloop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.mu.Lock()
				defer f.mu.Unlock()

				t := f.LookupOrCreate(name, n).(*Trace)
				t.Stop(trace)
				f.started = t.started
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	t.cmd = exec.Command("/bin/bash", "-c", `
		# gobpf currently uses global kprobes via debugfs/tracefs and not the Perf
		# Event file descriptor based kprobe (Linux >=4.17). So unfortunately, kprobes
		# can remain from previous executions. Ideally, gobpf should implement Perf
		# Event based kprobe and fallback to debugfs/tracefs, like bcc:
		# https://github.com/iovisor/bcc/blob/6e9b4509fc7a063302b574520bac6d49b01ca97e/src/cc/libbpf.c#L1021-L1027
		# Meanwhile, as a workaround, delete probes manually.
		# See: https://github.com/iovisor/gobpf/issues/223
		echo "-:pfree_uts_ns" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
		echo "-:pcap_capable" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true

		# Remove the opened files limit to avoid getting this error:
		# error while loading "tracepoint/raw_syscalls/sys_enter" (too many open files):
		# Indeed, traceloop creates a lof of tracers which each has maps and events:
		# https://github.com/kinvolk/traceloop/blob/6f4efc6fca46d92c75f4ec4e6c6e1d829bdeaddf/bpf/straceback-guess-bpf.h#L27-L28
		# So, this can generate a lof ot opened files.
		ulimit -n hard

		rm -f /run/traceloop.socket
		exec /bin/traceloop k8s
	`)
	t.cmd.Stdout = os.Stdout
	t.cmd.Stderr = os.Stderr
	err := t.cmd.Start()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start: %s", err)
		return
	}
	t.started = true

	trace.Status.State = "Started"
}

func (t *Trace) stop() error {
	if !t.started {
		return errors.New("not started")
	}

	err := t.cmd.Process.Signal(syscall.SIGINT)
	if err != nil {
		return fmt.Errorf("failed to send SIGINT to process: %w", err)
	}

	timeout := time.After(2 * time.Second)

	done := make(chan struct{})
	go func() {
		t.cmd.Process.Wait()
		done <- struct{}{}
	}()

	select {
	case <-timeout:
		t.cmd.Process.Kill()
	case <-done:
	}

	t.started = false

	return nil
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	err := t.stop()
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}

	trace.Status.State = "Stopped"
}
