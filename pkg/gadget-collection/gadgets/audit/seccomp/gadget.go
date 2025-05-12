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

package auditseccomp

import (
	"fmt"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	auditseccomptracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/tracer"
	types "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Trace struct {
	helpers gadgets.GadgetHelpers
	tracer  *auditseccomptracer.Tracer

	started bool
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
	return `The Audit Seccomp gadget provides a stream of events with syscalls that had
their seccomp filters generating an audit log. An audit log can be generated in
one of those two conditions:

* The Seccomp profile has the flag SECCOMP_FILTER_FLAG_LOG (supported from
  [runc v1.2.0](https://github.com/opencontainers/runc/releases/tag/v1.2.0),
  see [runc#3390](https://github.com/opencontainers/runc/pull/3390)) and returns
  any action other than SECCOMP_RET_ALLOW.
* The Seccomp profile does not have the flag SECCOMP_FILTER_FLAG_LOG but
  returns SCMP_ACT_LOG or SCMP_ACT_KILL*.
`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.tracer.Close()
		trace.tracer = nil
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			helpers: f.Helpers,
		}
	}
	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start audit seccomp",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop audit seccomp",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	traceName := gadgets.TraceName(trace.Namespace, trace.Name)
	eventCallback := func(event *types.Event) {
		event.K8s.Node = trace.Spec.Node

		t.helpers.PublishEvent(
			traceName,
			eventtypes.EventString(event),
		)
	}

	var err error

	mountNsMap, err := t.helpers.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}

	config := &auditseccomptracer.Config{
		MountnsMap: mountNsMap,
	}
	t.tracer, err = auditseccomptracer.NewTracer(config, t.helpers, eventCallback)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start audit seccomp tracer: %s", err)
		return
	}
	t.started = true

	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.tracer.Close()
	t.tracer = nil

	t.started = false

	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}
