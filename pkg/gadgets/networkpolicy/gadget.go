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

package networkpolicy

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy/advisor"
)

type Trace struct {
	started     bool
	sigtermSent bool
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	out         bytes.Buffer
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
	return `The network-policy gadget monitor the network activity in order to generate Kubernetes network policies.`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.cancel()
		trace.cmd.Wait()
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{}
	}
	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start network-policy",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
			Order: 1,
		},
		"update": {
			Doc: "Update results in Trace.Status.Output",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).UpdateOutput(trace)
			},
			Order: 2,
		},
		"report": {
			Doc: "Convert results into network policies",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Report(trace)
			},
			Order: 3,
		},
		"stop": {
			Doc: "Stop network-policy",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
			Order: 4,
		},
	}
}

func (f *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if f.started {
		trace.Status.OperationError = ""
		trace.Status.Output = ""
		trace.Status.State = "Started"
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel

	namespaces := ""
	if trace.Spec.Filter != nil {
		namespaces = trace.Spec.Filter.Namespace
	}
	args := []string{
		"-c",
		fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid networkpolicyadvisor --nomanager --probecleanup --gadget /bin/networkpolicyadvisor -- --namespace %s", namespaces),
	}
	log.Infof("Running /bin/sh %s", strings.Join(args, " "))
	f.cmd = exec.CommandContext(ctx, "/bin/sh", args...)
	f.cmd.Stdout = &f.out
	err := f.cmd.Start()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start: %s", err)
		return
	}
	f.started = true

	trace.Status.OperationError = ""
	trace.Status.Output = ""
	trace.Status.State = "Started"
	return
}

func (f *Trace) UpdateOutput(trace *gadgetv1alpha1.Trace) {
	if !f.started {
		trace.Status.OperationError = "Not started"
		return
	}
	output := f.out.String()
	log.Infof("Network Policy Advisor output:\n%s\n", output)

	trace.Status.OperationError = ""
	trace.Status.Output = output
	return
}

func (f *Trace) Report(trace *gadgetv1alpha1.Trace) {
	adv := advisor.NewAdvisor()
	err := adv.LoadBuffer([]byte(trace.Status.Output))
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Cannot parse report: %s", err)
		return
	}

	adv.GeneratePolicies()
	output := adv.FormatPolicies()

	trace.Status.OperationError = ""
	trace.Status.Output = output
	return
}

func (f *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !f.started {
		trace.Status.OperationError = "Not started"
		return
	}
	if !f.sigtermSent {
		f.cmd.Process.Signal(syscall.SIGINT)
		f.sigtermSent = true
	}
	f.cancel()
	f.cmd.Wait()
	f.started = false
	f.sigtermSent = false

	output := f.out.String()
	log.Infof("Network Policy Advisor output:\n%s\n", output)

	trace.Status.OperationError = ""
	trace.Status.Output = output
	return
}
