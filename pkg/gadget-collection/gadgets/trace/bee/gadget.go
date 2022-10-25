// Copyright 2022 The Inspektor Gadget authors
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

package bee

import (
	"encoding/json"
	"fmt"
	"io"
	"bytes"
	"compress/zlib"
	b64 "encoding/base64"

	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bee/tracer"
	beeTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bee/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

type Trace struct {
	helpers gadgets.GadgetHelpers

	started bool
	tracer  *tracer.Tracer
	conn    *networktracer.ConnectionToContainerCollection
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
	return `bee runs eBPF program in a OCI registry.`
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
			helpers: f.Helpers,
		}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start bee gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop bee gadget",
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

	if trace.Spec.Parameters == nil {
		trace.Status.OperationError = "missing parameters"
		return
	}

	params := trace.Spec.Parameters
	ociImage, ok1 := params["ociImage"]
	progContentEncoded, ok2 := params["progContent"]
	if (!ok1 && !ok2) || len(ociImage + progContentEncoded) == 0 {
		trace.Status.OperationError = "missing ociImage or progContent"
		return
	}
	var progContent []byte
	if len(progContentEncoded) != 0 {
		sDec, err := b64.StdEncoding.DecodeString(progContentEncoded)
		if err != nil {
			trace.Status.OperationError = "progContent not encoded correctly (needs base64+zip)"
			return
		}
		reader := bytes.NewReader(sDec)
		gzreader, err := zlib.NewReader(reader);
		if err != nil {
			trace.Status.OperationError = "progContent not encoded correctly (needs base64+zip)"
			return
		}
		progContent, err = io.ReadAll(gzreader);
		if err != nil {
			trace.Status.OperationError = "progContent not encoded correctly (needs base64+zip)"
			return
		}
	}


	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	eventCallback := func(event beeTypes.Event) {
		r, err := json.Marshal(event)
		if err != nil {
			log.Warnf("Gadget %s: error marshalling event: %s", trace.Spec.Gadget, err)
			return
		}
		t.helpers.PublishEvent(traceName, string(r))
	}

	networkEventCallback := func(container *containercollection.Container, event beeTypes.Event) {
		// Enrich event with data from container
		event.Node = trace.Spec.Node
		if !container.HostNetwork {
			event.Namespace = container.Namespace
			event.Pod = container.Podname
		}

		t.helpers.PublishEvent(
			traceName,
			eventtypes.EventString(event),
		)
	}

	var err error

	mountNsMap, err := t.helpers.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}
	tracerConfig := &tracer.Config{
		MountnsMap:   mountNsMap,
		ProgLocation: ociImage,
		ProgContent:  progContent,
	}
	t.tracer, err = tracer.NewTracer(tracerConfig, t.helpers, eventCallback)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
		return
	}

	config := &networktracer.ConnectToContainerCollectionConfig[beeTypes.Event]{
		Tracer:        t.tracer,
		Resolver:      t.helpers,
		Selector:      *gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		EventCallback: networkEventCallback,
		Base:          beeTypes.Base,
	}
	t.conn, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start bee tracer: %s", err)
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
