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
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	nettracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/network-graph/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/network-graph/types"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
)

type Trace struct {
	resolver gadgets.Resolver
	client   client.Client

	started bool
	done    chan bool

	tracer   *nettracer.Tracer
	enricher *Enricher

	netnsHost uint64
}

type TraceFactory struct {
	gadgets.BaseFactory

	netnsHost uint64
}

func NewFactory() gadgets.TraceFactory {
	netnsHost, _ := containerutils.GetNetNs(os.Getpid())
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
		netnsHost:   netnsHost,
	}
}

func (f *TraceFactory) Description() string {
	return `The network-graph gadget ...`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.resolver.Unsubscribe(genPubSubKey(name))
		trace.tracer.Close()
		trace.tracer = nil
		trace.enricher.Close()
		trace.enricher = nil
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			client:    f.Client,
			resolver:  f.Resolver,
			netnsHost: f.netnsHost,
		}
	}

	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start network-graph",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop network-graph",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

type pubSubKey string

func genPubSubKey(name string) pubSubKey {
	return pubSubKey(fmt.Sprintf("gadget/network-graph/%s", name))
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = "Started"
		return
	}

	var err error
	t.tracer, err = nettracer.NewTracer(gadgets.PinPath)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start network-graph tracer: %s", err)
		return
	}
	withKubernetes := t.client != nil
	t.enricher, err = NewEnricher(withKubernetes)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start network-graph enricher: %s", err)
		return
	}

	genKey := func(container *pb.ContainerDefinition) string {
		if container.Netns == t.netnsHost {
			return "host"
		}
		return container.Namespace + "/" + container.Podname
	}

	attachContainerFunc := func(container *pb.ContainerDefinition) error {
		key := genKey(container)

		err = t.tracer.Attach(key, container.Pid)
		if err != nil {
			log.Warnf("Warning: failed to attach tracer: %s", err)
			return err
		}
		return nil
	}

	detachContainerFunc := func(container *pb.ContainerDefinition) {
		key := genKey(container)

		err := t.tracer.Detach(key)
		if err != nil {
			log.Warnf("Warning: failed to detach tracer: %s", err)
			return
		}
	}

	containerEventCallback := func(event pubsub.PubSubEvent) {
		switch event.Type {
		case pubsub.EventTypeAddContainer:
			attachContainerFunc(&event.Container)
		case pubsub.EventTypeRemoveContainer:
			detachContainerFunc(&event.Container)
		}
	}

	existingContainers := t.resolver.Subscribe(
		genPubSubKey(trace.ObjectMeta.Namespace+"/"+trace.ObjectMeta.Name),
		*gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		containerEventCallback,
	)

	for _, c := range existingContainers {
		err := attachContainerFunc(c)
		if err != nil {
			log.Warnf("Warning: couldn't attach BPF program: %s", err)
			break
		}
	}
	t.started = true

	trace.Status.State = "Started"

	t.done = make(chan bool)
	go t.run(trace)
}

func (t *Trace) run(trace *gadgetv1alpha1.Trace) {
	traceBeforePatch := trace.DeepCopy()
	ticker := time.NewTicker(2 * time.Second)

	edges := []types.Edge{}
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			newEdges, err := t.tracer.Pop()
			if err != nil {
				log.Errorf("%s", err)
			}
			edges = append(edges, t.enricher.Enrich(newEdges)...)
			edges = types.Unique(edges)
			trace.Status.Output = types.EdgesString(edges)

			if t.client != nil {
				patch := client.MergeFrom(traceBeforePatch)
				err = t.client.Status().Patch(context.TODO(), trace, patch)
				if err != nil {
					log.Errorf("%s", err)
				}
			}
		}
	}
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}
	close(t.done)

	t.resolver.Unsubscribe(genPubSubKey(trace.ObjectMeta.Namespace + "/" + trace.ObjectMeta.Name))
	t.tracer.Close()
	t.tracer = nil
	t.enricher.Close()
	t.enricher = nil
	t.started = false

	trace.Status.State = "Stopped"
}
