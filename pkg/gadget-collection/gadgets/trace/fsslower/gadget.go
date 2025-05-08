// Copyright 2022 The Inspektor Gadget authors
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

package fsslower

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

var validFilesystems = []string{"btrfs", "ext4", "nfs", "xfs"}

type Trace struct {
	helpers gadgets.GadgetHelpers

	started bool
	tracer  trace.Tracer
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
	t := `fsslower shows open, read, write and fsync operations slower than a threshold

The following parameters are supported:
- filesystem: Which filesystem to trace [%s]
- minlatency: Min latency to trace, in ms. (default %d)`

	return fmt.Sprintf(t, strings.Join(validFilesystems, ", "), types.MinLatencyDefault)
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.tracer != nil {
		trace.tracer.Stop()
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
			Doc: "Start fsslower gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop fsslower gadget",
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
		r, err := json.Marshal(event)
		if err != nil {
			fmt.Printf("error marshaling event: %s\n", err)
			return
		}
		t.helpers.PublishEvent(traceName, string(r))
	}

	var err error

	if trace.Spec.Parameters == nil {
		trace.Status.OperationError = "missing parameters"
		return
	}

	params := trace.Spec.Parameters

	filesystem, ok := params["filesystem"]
	if !ok {
		trace.Status.OperationError = "missing filesystem"
		return
	}

	minLatency := types.MinLatencyDefault

	val, ok := params["minlatency"]
	if ok {
		minLatencyParsed, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("%q is not valid for minlatency", val)
			return
		}
		minLatency = uint(minLatencyParsed)
	}

	mountNsMap, err := t.helpers.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}

	config := &tracer.Config{
		MountnsMap: mountNsMap,
		Filesystem: filesystem,
		MinLatency: minLatency,
	}
	t.tracer, err = tracer.NewTracer(config, t.helpers, eventCallback)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
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

	t.tracer.Stop()
	t.tracer = nil
	t.started = false

	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}
