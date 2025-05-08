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

package sigsnoop

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"

	log "github.com/sirupsen/logrus"
)

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
	return `sigsnoop traces all signals sent on the system.

The following parameters are supported:
- failed: Trace only failed signal sending (default to false).
- signal: Which particular signal to trace (default to all).
- pid: Which particular pid to trace (default to all).
- kill-only: Trace only signals sent by the kill syscall (default to false).
`
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
			Doc: "Start sigsnoop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop sigsnoop gadget",
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
			log.Warnf("Gadget %s: error marshaling event: %s", trace.Spec.Gadget, err)
			return
		}
		t.helpers.PublishEvent(traceName, string(r))
	}

	params := trace.Spec.Parameters

	targetSignal := ""
	if signal, ok := params["signal"]; ok {
		targetSignal = signal
	}

	targetPid := int32(0)
	if pid, ok := params["pid"]; ok {
		pidParsed, err := strconv.ParseInt(pid, 10, 32)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("%q is not valid for PID", pid)
			return
		}

		targetPid = int32(pidParsed)
	}

	failedOnly := false
	if failed, ok := params["failed"]; ok {
		failedParsed, err := strconv.ParseBool(failed)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("%q is not valid for failed", failed)
			return
		}

		failedOnly = failedParsed
	}

	killOnly := false
	if kill, ok := params["kill-only"]; ok {
		killParsed, err := strconv.ParseBool(kill)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("%q is not valid for kill-only", kill)
			return
		}

		killOnly = killParsed
	}

	var err error

	mountNsMap, err := t.helpers.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}
	config := &tracer.Config{
		MountnsMap:   mountNsMap,
		TargetPid:    targetPid,
		TargetSignal: targetSignal,
		FailedOnly:   failedOnly,
		KillOnly:     killOnly,
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
