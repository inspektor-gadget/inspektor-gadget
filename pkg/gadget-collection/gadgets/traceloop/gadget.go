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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"

	tracelooptracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type containerSlim struct {
	mntnsid  uint64
	detached bool
}

type Trace struct {
	client  client.Client
	helpers gadgets.GadgetHelpers

	started bool

	containerIDs map[string]*containerSlim

	trace *gadgetv1alpha1.Trace
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
* traceloop's traces are recorded in a fast, in-memory, overwritable ring
  buffer like a flight recorder. The tracing could be permanently enabled and
  inspected in case of crash.
`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStatus: {},
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		traceUnique.Lock()
		defer traceUnique.Unlock()

		traceUnique.users--
		if traceUnique.users == 0 {
			trace.helpers.Unsubscribe(genPubSubKey(name))

			traceUnique.tracer.Stop()

			traceUnique.tracer = nil
		}
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
			Doc: "Start traceloop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
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
				t, err := f.Lookup(trace.Spec.Parameters["name"])
				if err != nil {
					trace.Status.OperationError = fmt.Sprintf("no global trace with name %q: %s", name, err)

					return
				}
				t.(*Trace).Collect(trace)
			},
		},
		gadgetv1alpha1.OperationDelete: {
			Doc: "Delete a perf ring buffer owned by traceloop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				// To overcome Status.Output character limit, we decided to create a
				// Stream Trace CRD each time we do the collect operation.
				// Nonetheless, this Trace CRD will use a previously created Trace.
				// To do so, we use the Parameters["name"] which will contain the name
				// of the long lived Trace CRD, thus we will be able to get the Trace
				// and so all the mntNsIDs associated to it.
				t, err := f.Lookup(trace.Spec.Parameters["name"])
				if err != nil {
					trace.Status.OperationError = fmt.Sprintf("no global trace with name %q: %s", name, err)

					return
				}
				t.(*Trace).Delete(trace)
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
	if trace.Spec.OutputMode != gadgetv1alpha1.TraceOutputModeStatus {
		trace.Status.OperationError = fmt.Sprintf("\"start\" operation can only be used with %q trace while %q was given", gadgetv1alpha1.TraceOutputModeStatus, trace.Spec.OutputMode)

		return
	}

	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	// Having this backlink is mandatory for delete operation.
	t.trace = trace

	// The output will contain an array of types.TraceloopInfo.
	// So, to avoid problems, we initialize it to be a JSON array.
	trace.Status.Output = "[]"
	t.containerIDs = make(map[string]*containerSlim, 0)

	genKey := func(container *containercollection.Container) string {
		return container.K8s.Namespace + "/" + container.K8s.PodName
	}

	attachContainerFunc := func(container *containercollection.Container) error {
		containerID := container.Runtime.ContainerID
		mntNsID := container.Mntns
		key := genKey(container)

		traceUnique.Lock()
		err := traceUnique.tracer.Attach(containerID, mntNsID)
		traceUnique.Unlock()
		if err != nil {
			log.Errorf("failed to attach tracer: %s", err)

			return err
		}

		t.containerIDs[containerID] = &containerSlim{
			mntnsid: mntNsID,
		}
		log.Debugf("tracer attached for %q (%d)", key, mntNsID)

		var infos []types.TraceloopInfo
		err = json.Unmarshal([]byte(trace.Status.Output), &infos)
		if err != nil {
			log.Errorf("failed to unmarshal output: %s", err)

			return err
		}

		infos = append(infos, types.TraceloopInfo{
			Namespace:     container.K8s.Namespace,
			Podname:       container.K8s.PodName,
			Containername: container.K8s.ContainerName,
			ContainerID:   containerID,
		})

		output, err := json.Marshal(infos)
		if err != nil {
			log.Errorf("failed to marshal infos: %s", err)

			return err
		}

		traceBeforePatch := trace.DeepCopy()
		trace.Status.Output = string(output)
		patch := client.MergeFrom(traceBeforePatch)

		// The surrounding function can be called from any context.
		// So, we need to manually patch the trace CRD to have our modifications be
		// taken into account.
		err = t.client.Status().Patch(context.TODO(), trace, patch)
		if err != nil {
			log.Errorf("Failed to patch trace %q output: %s", trace.Name, err)

			return err
		}

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

		_, ok := t.containerIDs[container.Runtime.ContainerID]
		if ok {
			t.containerIDs[container.Runtime.ContainerID].detached = true
		} else {
			log.Errorf("trace does not know about container with ID %q", container.Runtime.ContainerID)

			return
		}

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
		var syscallFilters string
		var err error

		filters, ok := trace.Spec.Parameters["syscall-filters"]
		if ok {
			syscallFilters = filters
		}

		traceUnique.tracer, err = tracelooptracer.NewTracer(t.helpers, strings.Split(syscallFilters, ","))
		if err != nil {
			traceUnique.Unlock()

			trace.Status.OperationError = fmt.Sprintf("Failed to start traceloop tracer: %s", err)

			return
		}
	}
	traceUnique.users++
	traceUnique.Unlock()

	existingContainers := t.helpers.Subscribe(
		genPubSubKey(trace.Namespace+"/"+trace.Name),
		*gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		containerEventCallback,
	)

	for _, c := range existingContainers {
		err := attachContainerFunc(c)
		if err != nil {
			log.Warnf("couldn't attach BPF program: %s", err)

			continue
		}
	}
	t.started = true

	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Collect(trace *gadgetv1alpha1.Trace) {
	if trace.Spec.OutputMode != gadgetv1alpha1.TraceOutputModeStream {
		trace.Status.OperationError = fmt.Sprintf("\"collect\" operation can only be used with %q trace while %q was given", gadgetv1alpha1.TraceOutputModeStream, trace.Spec.OutputMode)

		return
	}

	traceUnique.Lock()
	if traceUnique.tracer == nil {
		traceUnique.Unlock()

		trace.Status.OperationError = "Traceloop tracer is nil"

		return
	}
	traceUnique.Unlock()

	containerID := trace.Spec.Parameters["containerID"]
	_, ok := t.containerIDs[containerID]
	if !ok {
		ids := make([]string, len(t.containerIDs))
		i := 0
		for id := range t.containerIDs {
			ids[i] = id
			i++
		}

		trace.Status.OperationError = fmt.Sprintf("%q is not a valid ID for this trace, valid IDs are: %v", containerID, strings.Join(ids, ","))

		return
	}

	traceUnique.Lock()
	events, err := traceUnique.tracer.Read(containerID)
	traceUnique.Unlock()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to read perf buffer: %s", err)

		return
	}

	traceName := gadgets.TraceName(trace.Namespace, trace.Name)
	r, err := json.Marshal(events)
	if err != nil {
		log.Warnf("Gadget %s: error marshaling event: %s", trace.Spec.Gadget, err)
		return
	}
	// HACK Traceloop is really particular as it cannot use Status output because
	// the size is limited.
	// Also, if we send each event as a line, we will only be able to get the last
	// 100 (or 250) events from the CLI due to this code:
	// https://github.com/inspektor-gadget/inspektor-gadget/blob/9c7b6a126d82b54262ffdc5709d7c92480002830/pkg/gadgettracermanager/stream/stream.go#L24
	// https://github.com/inspektor-gadget/inspektor-gadget/blob/9c7b6a126d82b54262ffdc5709d7c92480002830/pkg/gadgettracermanager/stream/stream.go#L95-L100
	// To overcome this limitation, we just send all events as one big line.
	// Then, the CLI receives this big line, parses it and prints each event.
	// A proper solution would be to develop a specific "output" (neither status
	// nor stream) for traceloop, this is let as TODO.
	t.helpers.PublishEvent(traceName, string(r))

	trace.Status.State = gadgetv1alpha1.TraceStateCompleted
}

func (t *Trace) Delete(trace *gadgetv1alpha1.Trace) {
	if trace.Spec.OutputMode != gadgetv1alpha1.TraceOutputModeStatus {
		trace.Status.OperationError = fmt.Sprintf("\"delete\" operation can only be used with %q trace while %q was given", gadgetv1alpha1.TraceOutputModeStatus, trace.Spec.OutputMode)

		return
	}

	containerID := trace.Spec.Parameters["containerID"]
	container, ok := t.containerIDs[containerID]
	if !ok {
		ids := make([]string, len(t.containerIDs))
		i := 0
		for id := range t.containerIDs {
			ids[i] = id
			i++
		}

		trace.Status.OperationError = fmt.Sprintf("%q is not a valid ID for this trace, valid IDs are: %v", containerID, strings.Join(ids, ","))

		return
	}

	traceUnique.Lock()
	if traceUnique.tracer == nil {
		traceUnique.Unlock()

		trace.Status.OperationError = "Traceloop tracer is nil"

		return
	}

	// First, we need to detach the perf buffer.
	// We do not check the returned error because if the container was deleted it
	// was already detached.
	if !container.detached {
		_ = traceUnique.tracer.Detach(container.mntnsid)
	}

	// Then we can remove it.
	err := traceUnique.tracer.Delete(containerID)
	traceUnique.Unlock()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to delete perf buffer: %s", err)

		return
	}

	// We can now remove containerID from the map.
	delete(t.containerIDs, containerID)

	// Finally, we need to update the trace output.
	var infos []types.TraceloopInfo
	err = json.Unmarshal([]byte(t.trace.Status.Output), &infos)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to unmarshal output: %s", err)

		return
	}

	newInfos := make([]types.TraceloopInfo, len(infos)-1)
	i := 0
	for _, info := range infos {
		// We copy all the current information except the one corresponding to the
		// container we removed.
		if info.ContainerID == containerID {
			continue
		}

		newInfos[i] = info
		i++
	}

	output, err := json.Marshal(newInfos)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to marshal new infos: %s", err)

		return
	}

	traceBeforePatch := t.trace.DeepCopy()
	t.trace.Status.Output = string(output)
	patch := client.MergeFrom(traceBeforePatch)

	// We also need to manually patch the trace CRD to have our modifications be
	// taken into account.
	err = t.client.Status().Patch(context.TODO(), t.trace, patch)
	if err != nil {
		log.Errorf("failed to patch trace %q output: %s", trace.Name, err)

		return
	}

	trace.Status.State = gadgetv1alpha1.TraceStateCompleted
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if trace.Spec.OutputMode != gadgetv1alpha1.TraceOutputModeStatus {
		trace.Status.OperationError = fmt.Sprintf("\"stop\" operation can only be used with %q trace while %q was given", gadgetv1alpha1.TraceOutputModeStatus, trace.Spec.OutputMode)

		return
	}

	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.helpers.Unsubscribe(genPubSubKey(trace.Namespace + "/" + trace.Name))

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
