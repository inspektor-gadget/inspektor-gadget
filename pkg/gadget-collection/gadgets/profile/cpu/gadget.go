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
	"fmt"

	log "github.com/sirupsen/logrus"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/tracer"
	coretracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/tracer/core"
	standardtracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/tracer/standard"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/types"
)

type Trace struct {
	resolver gadgets.Resolver

	started bool
	tracer  tracer.Tracer
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
	if trace.tracer != nil && trace.started {
		trace.tracer.Stop()
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

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	mountNsMap, err := t.resolver.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}

	_, userStackOnly := trace.Spec.Parameters[types.ProfileUserParam]
	_, kernelStackOnly := trace.Spec.Parameters[types.ProfileKernelParam]
	config := &tracer.Config{
		MountnsMap:      mountNsMap,
		UserStackOnly:   userStackOnly,
		KernelStackOnly: kernelStackOnly,
	}

	t.tracer, err = coretracer.NewTracer(t.resolver, config, trace.Spec.Node)
	if err != nil {
		trace.Status.OperationWarning = fmt.Sprint("failed to create core tracer. Falling back to standard one")

		// fallback to standard tracer
		log.Infof("Gadget %s: falling back to standard tracer. CO-RE tracer failed: %s",
			trace.Spec.Gadget, err)

		t.tracer, err = standardtracer.NewTracer(config, trace.Spec.Node)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
			return
		}
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

	output, err := t.tracer.Stop()
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}

	t.tracer = nil
	t.started = false

	trace.Status.Output = output
	trace.Status.State = "Completed"
}
