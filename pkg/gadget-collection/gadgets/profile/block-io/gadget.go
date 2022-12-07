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

package biolatency

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/profile"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/tracer"
	standardtracer "github.com/inspektor-gadget/inspektor-gadget/pkg/standardgadgets/profile/block-io"
)

type Trace struct {
	helpers gadgets.GadgetHelpers

	started bool
	tracer  profile.Tracer
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
	return `The biolatency gadget traces block device I/O (disk I/O), and records the
distribution of I/O latency (time), giving this as a histogram when it is
stopped.`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStatus: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.tracer != nil && trace.started {
		trace.tracer.Stop()
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start biolatency",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop biolatency and store results",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if trace.Spec.Filter != nil {
		trace.Status.OperationError = "Invalid filter: Filtering is not supported"
		return
	}

	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	var err error
	t.tracer, err = tracer.NewTracer()
	if err != nil {
		trace.Status.OperationWarning = fmt.Sprint("failed to create core tracer. Falling back to standard one")

		// fallback to standard tracer
		log.Infof("Gadget %s: falling back to standard tracer. CO-RE tracer failed: %s",
			trace.Spec.Gadget, err)

		t.tracer, err = standardtracer.NewTracer()
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
			return
		}
	}
	t.started = true

	trace.Status.Output = ""
	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	defer func() {
		t.started = false
		t.tracer = nil
	}()

	output, err := t.tracer.Stop()
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}

	trace.Status.Output = output
	trace.Status.State = gadgetv1alpha1.TraceStateCompleted
}
