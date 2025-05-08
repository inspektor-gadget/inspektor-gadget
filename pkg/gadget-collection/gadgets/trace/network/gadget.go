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

package networkgraph

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	netTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	netTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubenameresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Trace struct {
	helpers gadgets.GadgetHelpers
	client  client.Client

	started bool

	tracer *netTracer.Tracer
	conn   *networktracer.ConnectionToContainerCollection

	kubeIPInst         operators.OperatorInstance
	kubeNameInst       operators.OperatorInstance
	socketEnricherInst operators.OperatorInstance
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
	return `The network-graph gadget monitors the network activity in the specified pods and records the list of TCP connections and UDP streams.`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.stop()
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
			Doc: "Start network-graph",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop network-graph",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) publishEvent(
	trace *gadgetv1alpha1.Trace,
	event *netTypes.Event,
) {
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

	var err error
	t.tracer, err = netTracer.NewTracer()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start network-graph tracer: %s", err)
		return
	}

	// TODO: Don't access the operators directly
	// - update cmd/kubectl-gadget/advise/network-policy.go to use the gRPC interface instead of the CR one
	// - delete this file pkg/gadget-collection/gadgets/trace/network/gadget.go
	kubeIPOp := operators.GetRaw(kubeipresolver.OperatorName).(*kubeipresolver.KubeIPResolver)
	kubeIPOp.Init(nil)
	t.kubeIPInst, err = kubeIPOp.Instantiate(nil, nil, nil)
	if err == nil {
		t.kubeIPInst.PreGadgetRun()
	}

	kubeNameOp := operators.GetRaw(kubenameresolver.OperatorName).(*kubenameresolver.KubeNameResolver)
	kubeNameOp.Init(nil)
	t.kubeNameInst, err = kubeNameOp.Instantiate(nil, nil, nil)
	if err == nil {
		t.kubeNameInst.PreGadgetRun()
	}

	socketEnricherOp := operators.GetRaw(socketenricher.OperatorName).(*socketenricher.SocketEnricher)
	socketEnricherOp.Init(nil)
	t.socketEnricherInst, err = socketEnricherOp.Instantiate(nil, t.tracer, nil)
	if err == nil {
		t.socketEnricherInst.PreGadgetRun()
	}

	eventCallback := func(event *netTypes.Event) {
		// Enrich event but only with the fields required for the advise network-policy gadget.
		event.K8s.Node = trace.Spec.Node
		if t.helpers != nil {
			t.helpers.EnrichByNetNs(&event.CommonData, event.NetNsID)
		}

		// Use KubeIPResolver and KubeNameResolver to enrich event based on Namespace/Pod and IP.
		if t.kubeIPInst != nil {
			t.kubeIPInst.EnrichEvent(event)
		}
		if t.kubeNameInst != nil {
			t.kubeNameInst.EnrichEvent(event)
		}

		t.publishEvent(trace, event)
	}
	t.tracer.SetEventHandler(eventCallback)

	config := &networktracer.ConnectToContainerCollectionConfig[netTypes.Event]{
		Tracer:   t.tracer,
		Resolver: t.helpers,
		Selector: *gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		Base:     netTypes.Base,
	}
	t.conn, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start network-graph tracer: %s", err)
		return
	}

	if err := t.tracer.RunWorkaround(); err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start network-graph tracer: %s", err)
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

	t.stop()
	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}

func (t *Trace) stop() {
	if t.conn != nil {
		t.conn.Close()
	}

	t.tracer.Close()
	t.tracer = nil
	t.started = false

	if t.kubeIPInst != nil {
		t.kubeIPInst.PostGadgetRun()
		t.kubeIPInst = nil
	}
	if t.kubeNameInst != nil {
		t.kubeNameInst.PostGadgetRun()
		t.kubeNameInst = nil
	}
	if t.socketEnricherInst != nil {
		t.socketEnricherInst.PostGadgetRun()
		t.socketEnricherInst = nil
	}
}
