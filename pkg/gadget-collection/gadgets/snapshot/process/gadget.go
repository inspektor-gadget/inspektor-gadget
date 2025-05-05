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
	"strconv"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
)

type Trace struct {
	helpers gadgets.GadgetHelpers
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

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStatus: {},
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			helpers: f.Helpers,
		}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationCollect: {
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
	traceName := gadgets.TraceName(trace.Namespace, trace.Name)
	mountNsMap, err := t.helpers.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}

	showThreads := false

	params := trace.Spec.Parameters
	if params != nil {
		if val, ok := params[types.ShowThreadsParam]; ok {
			var err error
			showThreads, err = strconv.ParseBool(val)
			if err != nil {
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for %s: %v", val, types.ShowThreadsParam, err)
				return
			}
		}
	}
	config := &tracer.Config{
		MountnsMap:  mountNsMap,
		ShowThreads: showThreads,
	}
	events, err := tracer.RunCollector(config, t.helpers)
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}

	if len(events) == 0 {
		trace.Status.OperationWarning = "No container matches the requested filter"
		trace.Status.State = gadgetv1alpha1.TraceStateCompleted
		return
	}

	output, err := json.MarshalIndent(events, "", " ")
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed marshaling processes: %s", err)
		return
	}

	trace.Status.Output = string(output)
	trace.Status.State = gadgetv1alpha1.TraceStateCompleted
}
