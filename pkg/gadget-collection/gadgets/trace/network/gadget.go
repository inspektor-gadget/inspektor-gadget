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
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	nettracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type pubSubKey string

type Trace struct {
	helpers gadgets.GadgetHelpers
	client  client.Client

	started bool
	done    chan bool

	// detachContainer is read by the go routine and it detaches the tracer
	// from the container. The string is the container key as per genKey().
	detachContainer chan string

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
			client:    f.Client,
			helpers:   f.Helpers,
			netnsHost: f.netnsHost,
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
			Type: eventType,
			CommonData: eventtypes.CommonData{
				Node: trace.Spec.Node,
			},
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

		// Don't call t.tracer.Detach here. Make sure that t.tracer.Pop
		// is called before.
		t.detachContainer <- key
	}

	containerEventCallback := func(event containercollection.PubSubEvent) {
		switch event.Type {
		case containercollection.EventTypeAddContainer:
			attachContainerFunc(event.Container)
		case containercollection.EventTypeRemoveContainer:
			detachContainerFunc(event.Container)
		}
	}

	t.pubSubKey = pubSubKey(fmt.Sprintf("gadget/network-graph/%s/%s", trace.ObjectMeta.Namespace, trace.ObjectMeta.Name))
	existingContainers := t.helpers.Subscribe(
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

	trace.Status.State = gadgetv1alpha1.TraceStateStarted

	t.done = make(chan bool)
	t.detachContainer = make(chan string)
	t.wg.Add(1)
	go t.run(trace)
}

func (t *Trace) run(trace *gadgetv1alpha1.Trace) {
	defer t.wg.Done()
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-t.done:
			ticker.Stop()
			return
		case key := <-t.detachContainer:
			if !t.update(trace) {
				return
			}
			err := t.tracer.Detach(key)
			if err != nil {
				t.publishMessage(trace, eventtypes.ERR, key, fmt.Sprintf("failed to detach tracer: %s", err))
				return
			}
			t.publishMessage(trace, eventtypes.DEBUG, key, "tracer detached")
		case <-ticker.C:
			if !t.update(trace) {
				return
			}
		}
	}
}

func (t *Trace) update(trace *gadgetv1alpha1.Trace) bool {
	if t.tracer == nil {
		// This should not happen with t.wg
		log.Errorf("tracer is nil at tick")
		t.publishMessage(trace, eventtypes.ERR, "host", "tracer is nil at tick")
		return false
	}
	newEvents, err := t.tracer.Pop()
	if err != nil {
		log.Errorf("failed to read BPF map: %s", err)
		t.publishMessage(trace, eventtypes.ERR, "host", fmt.Sprintf("failed to read BPF map: %s", err))
		return false
	}
	t.enricher.Enrich(newEvents)

	for _, event := range newEvents {
		// for now, ignore events on the host netns
		if event.Pod != "" {
			t.publishEvent(trace, event)
		}
	}
	return true
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
	t.helpers.Unsubscribe(t.pubSubKey)

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
