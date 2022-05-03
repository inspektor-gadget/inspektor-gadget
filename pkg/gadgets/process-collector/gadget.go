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

package processcollector

import (
	"encoding/json"
	"fmt"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/tracer"
)

type Trace struct {
	resolver gadgets.Resolver
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{}
}

func (f *TraceFactory) Description() string {
	return `The process-collector gadget gathers information about running processes`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status": {},
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			resolver: f.Resolver,
		}
	}

	return map[string]gadgets.TraceOperation{
		"collect": {
			Doc: "Create a snapshot of the currently running processes. " +
				"Once taken, the snapshot is not updated automatically. " +
				"However one can call the collect operation again at any time to update the snapshot.",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Collect(trace)
			},
		},
	}
}

func (t *Trace) Collect(trace *gadgetv1alpha1.Trace) {
	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	mountNsMap, err := t.resolver.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}
	events, err := tracer.RunCollector(t.resolver, trace.Spec.Node, mountNsMap)
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}

	if len(events) == 0 {
		trace.Status.OperationWarning = "No container matches the requested filter"
		trace.Status.State = "Completed"
		return
	}

	output, err := json.MarshalIndent(events, "", " ")
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed marshalling processes: %s", err)
		return
	}

	trace.Status.Output = string(output)
	trace.Status.State = "Completed"
}
