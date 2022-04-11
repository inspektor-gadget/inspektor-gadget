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

package snisnoop

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	snitracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snisnoop/tracer"
	types "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snisnoop/types"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Trace struct {
	resolver gadgets.Resolver
	client   client.Client

	started bool

	tracer *snitracer.Tracer

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
	return `The snisnoop gadget retrieves Server Name Indication (SNI) from TLS requests.`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Stream": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.resolver.Unsubscribe(genPubSubKey(name))
		trace.tracer.Close()
		trace.tracer = nil
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
			Doc: "Start snisnoop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop snisnoop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

type pubSubKey string

func genPubSubKey(name string) pubSubKey {
	return pubSubKey(fmt.Sprintf("gadget/snisnoop/%s", name))
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = "Started"
		return
	}

	var err error
	t.tracer, err = snitracer.NewTracer()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start sni tracer: %s", err)
		return
	}

	fillEvent := func(event *types.Event, key string) {
		keyParts := strings.SplitN(key, "/", 2)
		if len(keyParts) == 2 {
			event.Namespace = keyParts[0]
			event.Pod = keyParts[1]
		} else if key != "host" {
			event.Type = eventtypes.ERR
			event.Message = fmt.Sprintf("unknown key %s", key)
		}
	}
	printMessage := func(key string, t eventtypes.EventType, message string) string {
		event := &types.Event{
			Event: eventtypes.Event{
				Type:    t,
				Node:    trace.Spec.Node,
				Message: message,
			},
		}

		fillEvent(event, key)

		b, err := json.Marshal(event)
		if err != nil {
			return fmt.Sprintf("error marshalling results: %s", err)
		}
		return string(b)
	}
	printEvent := func(key, name string) string {
		event := &types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				Node: trace.Spec.Node,
			},
			Name: name,
		}
		fillEvent(event, key)

		b, err := json.Marshal(event)
		if err != nil {
			return fmt.Sprintf("error marshalling results: %s", err)
		}
		return string(b)
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	newSNIRequestCallback := func(key string) func(event types.Event) {
		return func(event types.Event) {
			t.resolver.PublishEvent(
				traceName,
				printEvent(key, event.Name),
			)
		}
	}

	genKey := func(container *pb.ContainerDefinition) string {
		if container.Netns == t.netnsHost {
			return "host"
		}
		return container.Namespace + "/" + container.Podname
	}

	attachContainerFunc := func(container *pb.ContainerDefinition) error {
		key := genKey(container)

		err = t.tracer.Attach(key, container.Pid, newSNIRequestCallback(key), trace.Spec.Node)
		if err != nil {
			t.resolver.PublishEvent(
				traceName,
				printMessage(key, eventtypes.ERR, fmt.Sprintf("failed to attach tracer: %s", err)),
			)
			return err
		}
		t.resolver.PublishEvent(
			traceName,
			printMessage(key, eventtypes.DEBUG, "tracer attached"),
		)
		return nil
	}

	detachContainerFunc := func(container *pb.ContainerDefinition) {
		key := genKey(container)

		err := t.tracer.Detach(key)
		if err != nil {
			t.resolver.PublishEvent(
				traceName,
				printMessage(key, eventtypes.ERR, fmt.Sprintf("failed to detach tracer: %s", err)),
			)
			return
		}
		t.resolver.PublishEvent(
			traceName,
			printMessage(key, eventtypes.DEBUG, "tracer detached"),
		)
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
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.resolver.Unsubscribe(genPubSubKey(trace.ObjectMeta.Namespace + "/" + trace.ObjectMeta.Name))
	t.tracer.Close()
	t.tracer = nil
	t.started = false

	trace.Status.State = "Stopped"
}
