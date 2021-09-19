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

package signal

import (
	"fmt"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	signaltracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/signal/tracer"
)

type Trace struct {
	started bool
	tracer  *signaltracer.Tracer
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{}
}

func (f *TraceFactory) Description() string {
	return `The signal gadget traces the close system call and sends the signal SIGILL each time the target process calls close().

Start the gadget:
` + "```" + `
sudo ./local-gadget
» trace signal t
» operation t start
` + "```" + `

Run the target process:
` + "```" + `
make -C docs/examples/gosignal/
docs/examples/gosignal/gosignal
` + "```" + `

A stack for close() called from the os.File finalizer looks like:

` + "```" + `
goroutine 5 [syscall]:
syscall.Syscall(0x3, 0xa, 0x0, 0x0, 0x7f6a40979108, 0x168, 0x100000002)
	/usr/lib/golang/src/syscall/asm_linux_amd64.s:20 +0x5
syscall.Close(0xa, 0x5, 0xc000042688)
	/usr/lib/golang/src/syscall/zsyscall_linux_amd64.go:285 +0x45
internal/poll.(*FD).destroy(0xc00006c180, 0x100, 0x0)
	/usr/lib/golang/src/internal/poll/fd_unix.go:83 +0x43
internal/poll.(*FD).decref(0xc00006c180, 0x7f6a184ff001, 0x2)
	/usr/lib/golang/src/internal/poll/fd_mutex.go:213 +0x5d
internal/poll.(*FD).Close(0xc00006c180, 0x7f6a40970108, 0x43f109)
	/usr/lib/golang/src/internal/poll/fd_unix.go:106 +0x4f
os.(*file).close(0xc00006c180, 0x0, 0x0)
	/usr/lib/golang/src/os/file_unix.go:251 +0x38
` + "```" + `

A stack for close() called from ioutil.ReadFile() looks like:

` + "```" + `
goroutine 1 [syscall]:
syscall.Syscall(0x3, 0xa, 0x0, 0x0, 0x0, 0xa, 0xc000102000)
	/usr/lib/golang/src/syscall/asm_linux_amd64.s:20 +0x5
syscall.Close(0xa, 0xc00008e060, 0x1)
	/usr/lib/golang/src/syscall/zsyscall_linux_amd64.go:285 +0x45
internal/poll.(*FD).destroy(0xc00008e060, 0x200, 0x0)
	/usr/lib/golang/src/internal/poll/fd_unix.go:83 +0x43
internal/poll.(*FD).decref(0xc00008e060, 0x7fd39ded0f01, 0xa)
	/usr/lib/golang/src/internal/poll/fd_mutex.go:213 +0x5d
internal/poll.(*FD).Close(0xc00008e060, 0x4ef7d8, 0xc0001900b0)
	/usr/lib/golang/src/internal/poll/fd_unix.go:106 +0x4f
os.(*file).close(0xc00008e060, 0x4ef7d8, 0xc0001900b0)
	/usr/lib/golang/src/os/file_unix.go:251 +0x38
os.(*File).Close(0xc0001aa030, 0xc0001900b0, 0xc0001900b0)
	/usr/lib/golang/src/os/file_posix.go:25 +0x33
os.ReadFile(0x4cf3f9, 0x9, 0xc000102000, 0x0, 0x200, 0x0, 0x0)
	/usr/lib/golang/src/os/file.go:687 +0x24f
io/ioutil.ReadFile(...)
	/usr/lib/golang/src/io/ioutil/ioutil.go:37
main.main()
	/home/alban/go/src/github.com/kinvolk/inspektor-gadget/docs/examples/gosignal/gosignal.go:81 +0x5f
` + "```" + `
`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status": {},
	}
}

func (f *TraceFactory) DeleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.tracer.Close()
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{}
	}
	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start monitoring the close syscall",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop monitoring the close syscall",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.OperationError = ""
		trace.Status.Output = ""
		trace.Status.State = "Started"
		return
	}

	var err error
	t.tracer, err = signaltracer.NewTracer()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start signal tracer: %s", err)
		return
	}

	t.started = true

	trace.Status.OperationError = ""
	trace.Status.Output = ""
	trace.Status.State = "Started"
	return
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.tracer.Close()
	t.started = false

	trace.Status.OperationError = ""
	trace.Status.State = "Stopped"
	return
}
