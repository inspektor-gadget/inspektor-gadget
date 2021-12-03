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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	dnstracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/tracer"
	dnstypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/types"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Trace struct {
	resolver gadgets.Resolver
	client   client.Client

	started bool

	tracer *dnstracer.Tracer

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
	return `The dns gadget traces DNS requests.`
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
			Doc: "Start dns",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop dns and store results",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

type pubSubKey string

func genPubSubKey(name string) pubSubKey {
	return pubSubKey(fmt.Sprintf("gadget/dns/%s", name))
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.OperationError = ""
		trace.Status.Output = ""
		trace.Status.State = "Started"
		return
	}

	var err error
	t.tracer, err = dnstracer.NewTracer()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start dns tracer: %s", err)
		return
	}

	printEvent := func(notice, err, key, name, pktType string) string {
		event := &dnstypes.Event{
			Event: eventtypes.Event{
				Notice: notice,
				Err:    err,
				Node:   trace.Spec.Node,
			},
			DNSName: name,
			PktType: pktType,
		}

		keyParts := strings.SplitN(key, "/", 2)
		if len(keyParts) == 2 {
			event.Namespace = keyParts[0]
			event.Pod = keyParts[1]
		} else if key == "host" {
			event.Host = true
		} else if key != "" {
			event.Err = fmt.Sprintf("unknown key %s", key)
		}

		b, e := json.Marshal(event)
		if e != nil {
			return `{"err": "cannot marshal event"}`
		}
		return string(b)
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	newDNSRequestCallback := func(key string) func(name, pktType string) {
		return func(name, pktType string) {
			t.resolver.PublishEvent(
				traceName,
				printEvent("", "", key, name, pktType),
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

		err = t.tracer.Attach(key, container.Pid, newDNSRequestCallback(key))
		if err != nil {
			t.resolver.PublishEvent(
				traceName,
				printEvent("failed to attach tracer", err.Error(), key, "", ""),
			)
			return err
		}
		t.resolver.PublishEvent(
			traceName,
			printEvent("tracer attached", "", key, "", ""),
		)
		return nil
	}

	detachContainerFunc := func(container *pb.ContainerDefinition) {
		key := genKey(container)

		err := t.tracer.Detach(key)
		if err != nil {
			t.resolver.PublishEvent(
				traceName,
				printEvent("failed to detach tracer", err.Error(), key, "", ""),
			)
			return
		}
		t.resolver.PublishEvent(
			traceName,
			printEvent("tracer detached", "", key, "", ""),
		)
	}

	containerEventCallback := func(event pubsub.PubSubEvent) {
		switch event.Type {
		case pubsub.EVENT_TYPE_ADD_CONTAINER:
			attachContainerFunc(&event.Container)
		case pubsub.EVENT_TYPE_REMOVE_CONTAINER:
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

	trace.Status.OperationError = ""
	trace.Status.Output = ""
	trace.Status.State = "Started"
	return
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

	trace.Status.OperationError = ""
	trace.Status.State = "Stopped"
	return
}
