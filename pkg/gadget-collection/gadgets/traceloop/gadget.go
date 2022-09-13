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

package traceloop

import (
	"encoding/json"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"

	tracelooptracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type Trace struct {
	helpers gadgets.GadgetHelpers

	started bool

	mntNsIDs map[uint64]bool
}

type TraceFactory struct {
	gadgets.BaseFactory
}

type traceSingleton struct {
	sync.Mutex

	tracer *tracelooptracer.Tracer
	users  int
}

var traceUnique traceSingleton

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	return `The traceloop gadget traces system calls in a similar way to strace but with
some differences:

* traceloop uses eBPF instead of ptrace
* traceloop's tracing granularity is the container instead of a process
* traceloop's traces are recorded in a fast, in-memory, over writable ring
  buffer like a flight recorder. The tracing could be permanently enabled and
  inspected in case of crash.
`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.helpers.Unsubscribe(genPubSubKey(name))
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
			Doc: "Start traceloop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				log.SetLevel(log.DebugLevel)
				log.Debugf("***name: %s\n", name)
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationCollect: {
			Doc: "Collect traceloop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				// To overcome Status.Output character limit, we decided to create a
				// Stream Trace CRD each time we do the collect operation.
				// Nonetheless, this Trace CRD will use a previously created Trace.
				// To do so, we use the Parameters["name"] which will contain the name
				// of the long lived Trace CRD, thus we will be able to get the Trace
				// and so all the mntNsIDs associated to it.
				f.LookupOrCreate(trace.Spec.Parameters["name"], n).(*Trace).Collect(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop traceloop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

type pubSubKey string

func genPubSubKey(name string) pubSubKey {
	return pubSubKey(fmt.Sprintf("gadget/traceloop/%s", name))
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	t.mntNsIDs = make(map[uint64]bool, 0)

	genKey := func(container *containercollection.Container) string {
		return container.Namespace + "/" + container.Podname
	}

	attachContainerFunc := func(container *containercollection.Container) error {
		mntNsID := container.Mntns
		key := genKey(container)

		traceUnique.Lock()
		err := traceUnique.tracer.Attach(mntNsID)
		traceUnique.Unlock()
		if err != nil {
			log.Errorf("failed to attach tracer: %s", err)

			return err
		}

		t.mntNsIDs[mntNsID] = true
		log.Debugf("tracer attached for %q (%d)", key, mntNsID)

		return nil
	}

	detachContainerFunc := func(container *containercollection.Container) {
		mntNsID := container.Mntns
		key := genKey(container)

		traceUnique.Lock()
		err := traceUnique.tracer.Detach(mntNsID)
		traceUnique.Unlock()
		if err != nil {
			log.Errorf("failed to detach tracer: %s", err)

			return
		}

		delete(t.mntNsIDs, mntNsID)
		log.Debugf("tracer detached for %q (%d)", key, mntNsID)
	}

	containerEventCallback := func(event containercollection.PubSubEvent) {
		switch event.Type {
		case containercollection.EventTypeAddContainer:
			attachContainerFunc(event.Container)
		case containercollection.EventTypeRemoveContainer:
			detachContainerFunc(event.Container)
		}
	}

	traceUnique.Lock()
	if traceUnique.tracer == nil {
		var err error

		traceUnique.tracer, err = tracelooptracer.NewTracer(t.helpers)
		if err != nil {
			traceUnique.Unlock()

			trace.Status.OperationError = fmt.Sprintf("Failed to start seccomp tracer: %s", err)

			return
		}
	}
	traceUnique.users++
	traceUnique.Unlock()

	existingContainers := t.helpers.Subscribe(
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

	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Collect(trace *gadgetv1alpha1.Trace) {
	traceUnique.Lock()
	if traceUnique.tracer == nil {
		traceUnique.Unlock()

		log.Errorf("Traceloop tracer is nil")

		return
	}
	traceUnique.Unlock()

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	for mntNsID := range t.mntNsIDs {
		traceUnique.Lock()
		events, err := traceUnique.tracer.Read(mntNsID)
		traceUnique.Unlock()
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to read perf buffer: %s", err)

			return
		}

		for _, event := range events {
			r, err := json.Marshal(event)
			if err != nil {
				log.Warnf("Gadget %s: error marshalling event: %s", trace.Spec.Gadget, err)
				return
			}
			log.Debugf("event: %v", r)
			t.helpers.PublishEvent(traceName, string(r))
		}
	}

	trace.Status.State = gadgetv1alpha1.TraceStateCompleted
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.helpers.Unsubscribe(genPubSubKey(trace.ObjectMeta.Namespace + "/" + trace.ObjectMeta.Name))

	traceUnique.Lock()
	traceUnique.users--
	if traceUnique.users == 0 {
		traceUnique.tracer.Stop()

		traceUnique.tracer = nil
	}
	traceUnique.Unlock()

	t.started = false

	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}
