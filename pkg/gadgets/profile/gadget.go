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

package profile

import (
	"bytes"
	"fmt"
	"os/exec"
	"syscall"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/types"
)

type Trace struct {
	started bool
	cmd     *exec.Cmd
	stdout  bytes.Buffer
	stderr  bytes.Buffer
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	return `Analyze CPU performance by sampling stack traces`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.cmd.Process.Kill()
		trace.cmd.Wait()
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{}
	}

	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start profile",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop profile and store results",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = "Started"
		return
	}

	mountNsMap := gadgets.TracePinPath(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	t.cmd = exec.Command("/usr/share/bcc/tools/profile", "-f", "-d",
		"--mntnsmap", mountNsMap)

	if _, ok := trace.Spec.Parameters[types.ProfileUserParam]; ok {
		t.cmd.Args = append(t.cmd.Args, "-U")
	}

	if _, ok := trace.Spec.Parameters[types.ProfileKernelParam]; ok {
		t.cmd.Args = append(t.cmd.Args, "-K")
	}

	t.stdout.Reset()
	t.stderr.Reset()
	t.cmd.Stdout = &t.stdout
	t.cmd.Stderr = &t.stderr
	if err := t.cmd.Start(); err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start: %s", err)
		return
	}
	t.started = true

	trace.Status.Output = ""
	trace.Status.State = "Started"
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}
	err := t.cmd.Process.Signal(syscall.SIGINT)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf(
			"Failed to send SIGINT to process: %s (stdout: %q stderr: %q)",
			err,
			t.stdout.String(),
			t.stderr.String(),
		)
		return
	}

	err = t.cmd.Wait()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf(
			"Failed to wait for process: %s (stdout: %q stderr: %q)",
			err,
			t.stdout.String(),
			t.stderr.String(),
		)
		return
	}
	t.cmd = nil
	t.started = false

	output := t.stdout.String()

	trace.Status.Output = output
	trace.Status.State = "Completed"
}
