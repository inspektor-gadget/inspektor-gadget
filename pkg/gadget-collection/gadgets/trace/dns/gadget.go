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

package dns

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	dnsTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	dnsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Trace struct {
	helpers gadgets.GadgetHelpers
	client  client.Client

	started bool

	tracer *dnsTracer.Tracer
	conn   *networktracer.ConnectionToContainerCollection
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
	return `The dns gadget traces DNS requests.`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		if trace.conn != nil {
			trace.conn.Close()
		}
		trace.tracer.Close()
		trace.tracer = nil
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			client:  f.Client,
			helpers: f.Helpers,
		}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start dns",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop dns and store results",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) publishEvent(trace *gadgetv1alpha1.Trace, event *dnsTypes.Event) {
	traceName := gadgets.TraceName(trace.Namespace, trace.Name)
	t.helpers.PublishEvent(
		traceName,
		eventtypes.EventString(event),
	)
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	eventCallback := func(event *dnsTypes.Event) {
		t.publishEvent(trace, event)
	}

	var err error
	t.tracer, err = dnsTracer.NewTracer(&dnsTracer.Config{})
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start dns tracer: %s", err)
		return
	}

	t.tracer.SetEventHandler(eventCallback)

	config := &networktracer.ConnectToContainerCollectionConfig[dnsTypes.Event]{
		Tracer:   t.tracer,
		Resolver: t.helpers,
		Selector: *gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		Base:     dnsTypes.Base,
	}
	t.conn, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start dns tracer: %s", err)
		return
	}

	if err := t.tracer.RunWorkaround(); err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start dns tracer: %s", err)
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

	if t.conn != nil {
		t.conn.Close()
	}
	t.tracer.Close()
	t.tracer = nil
	t.started = false

	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}
