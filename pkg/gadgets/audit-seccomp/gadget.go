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

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	auditseccomptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit-seccomp/tracer"
	types "github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit-seccomp/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Trace struct {
	resolver gadgets.Resolver
	tracer   *auditseccomptracer.Tracer

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

* The Seccomp profile has the flag SECCOMP_FILTER_FLAG_LOG (currently
  [unsupported by runc](https://github.com/opencontainers/runc/pull/3390)) and
  returns any action other than SECCOMP_RET_ALLOW.
* The Seccomp profile does not have the flag SECCOMP_FILTER_FLAG_LOG but
  returns SCMP_ACT_LOG or SCMP_ACT_KILL*.
`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Stream": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.tracer.Close()
		trace.tracer = nil
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			resolver: f.Resolver,
		}
	}
	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start audit seccomp",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop audit seccomp",
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

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	eventCallback := func(event types.Event) {
		t.resolver.PublishEvent(
			traceName,
			eventtypes.EventString(event),
		)
	}

	var err error

	mountNsMap, err := t.resolver.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}

	config := &auditseccomptracer.Config{
		MountnsMap:    mountNsMap,
		ContainersMap: t.resolver.ContainersMap(),
	}
	t.tracer, err = auditseccomptracer.NewTracer(config, eventCallback, trace.Spec.Node)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start audit seccomp tracer: %s", err)
		return
	}
	t.started = true

	trace.Status.State = "Started"
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.tracer.Close()
	t.tracer = nil

	t.started = false

	trace.Status.State = "Stopped"
}
