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
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets"
	nettracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type pubSubKey string

type Trace struct {
	resolver gadgets.Resolver
	client   client.Client

	started bool
	done    chan bool

	tracer   *nettracer.Tracer
	enricher *Enricher
	wg       sync.WaitGroup

	netnsHost uint64

	pubSubKey pubSubKey
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
	return `The network-graph gadget monitors the network activity in the specified pods and records the list of TCP connections and UDP streams.`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Stream": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.stop()
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

func genPubSubKey(name string) pubSubKey {
	return pubSubKey(fmt.Sprintf("gadget/network-graph/%s", name))
}

func (t *Trace) publishMessage(
	trace *gadgetv1alpha1.Trace,
	eventType eventtypes.EventType,
	key string,
	msg string,
) {
	event := &types.Event{
		Event: eventtypes.Event{
			Type:    eventType,
			Node:    trace.Spec.Node,
			Message: msg,
		},
	}

	keyParts := strings.SplitN(key, "/", 2)
	if len(keyParts) == 2 {
		event.Namespace = keyParts[0]
		event.Pod = keyParts[1]
	} else if key != "host" {
		event.Type = eventtypes.ERR
		event.Message = fmt.Sprintf("unknown key %s", key)
	}

	t.publishEvent(trace, event)
}

func (t *Trace) publishEvent(
	trace *gadgetv1alpha1.Trace,
	event *types.Event,
) {
	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	t.resolver.PublishEvent(
		traceName,
		eventtypes.EventString(event),
	)
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = "Started"
		return
	}

	var err error
	withKubernetes := t.client != nil
	t.enricher, err = NewEnricher(withKubernetes, trace.Spec.Node)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start network-graph enricher: %s", err)
		return
	}
	t.tracer, err = nettracer.NewTracer()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start network-graph tracer: %s", err)
		return
	}

	genKey := func(container *containercollection.Container) string {
		if container.Netns == t.netnsHost {
			return "host"
		}
		return container.Namespace + "/" + container.Podname
	}

	attachContainerFunc := func(container *containercollection.Container) error {
		key := genKey(container)

		err := t.tracer.Attach(key, container.Pid)
		if err != nil {
			t.publishMessage(trace, eventtypes.ERR, key, fmt.Sprintf("failed to attach tracer: %s", err))
			return err
		}
		t.publishMessage(trace, eventtypes.DEBUG, key, "tracer attached")
		return nil
	}

	detachContainerFunc := func(container *containercollection.Container) {
		key := genKey(container)

		err := t.tracer.Detach(key)
		if err != nil {
			t.publishMessage(trace, eventtypes.ERR, key, fmt.Sprintf("failed to detach tracer: %s", err))
			return
		}
		t.publishMessage(trace, eventtypes.DEBUG, key, "tracer detached")
	}

	containerEventCallback := func(event containercollection.PubSubEvent) {
		switch event.Type {
		case containercollection.EventTypeAddContainer:
			attachContainerFunc(&event.Container)
		case containercollection.EventTypeRemoveContainer:
			detachContainerFunc(&event.Container)
		}
	}

	t.pubSubKey = pubSubKey(fmt.Sprintf("gadget/network-graph/%s/%s", trace.ObjectMeta.Namespace, trace.ObjectMeta.Name))
	existingContainers := t.resolver.Subscribe(
		t.pubSubKey,
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
	t.wg.Add(1)
	go t.run(trace)
}

func (t *Trace) run(trace *gadgetv1alpha1.Trace) {
	defer t.wg.Done()

	traceBeforePatch := trace.DeepCopy()
	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-t.done:
			ticker.Stop()
			return
		case <-ticker.C:
			if t.tracer == nil {
				// This should not happen with t.wg
				log.Errorf("tracer is nil at tick")
				t.publishMessage(trace, eventtypes.ERR, "host", "tracer is nil at tick")
				return
			}
			newEdges, err := t.tracer.Pop()
			if err != nil {
				log.Errorf("failed to read BPF map: %s", err)
				t.publishMessage(trace, eventtypes.ERR, "host", fmt.Sprintf("failed to read BPF map: %s", err))
				return
			}
			newEvents := t.enricher.Enrich(newEdges)

			if t.client != nil {
				patch := client.MergeFrom(traceBeforePatch)
				err = t.client.Status().Patch(context.TODO(), trace, patch)
				if err != nil {
					log.Errorf("%s", err)
				}
			}

			for _, event := range newEvents {
				// for now, ignore events on the host netns
				if event.Pod != "" {
					t.publishEvent(trace, &event)
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

	t.stop()
	trace.Status.State = "Stopped"
}

func (t *Trace) stop() {
	t.resolver.Unsubscribe(t.pubSubKey)

	// tell run() to stop using t.tracer
	t.done <- true
	// wait for run() to end before closing t.tracer and t.enricher
	t.wg.Wait()

	t.tracer.Close()
	t.tracer = nil
	t.enricher.Close()
	t.enricher = nil
	t.started = false
}
