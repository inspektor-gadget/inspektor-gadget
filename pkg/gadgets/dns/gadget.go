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

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	dnstracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/tracer"
	dnstypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/types"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Trace struct {
	resolver gadgets.Resolver
	client   client.Client

	started bool

	tracer *dnstracer.Tracer
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
			client:   f.Client,
			resolver: f.Resolver,
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

	genKey := func(namespace, podname string, pid uint32) (key string, err error) {
		key = namespace + "/" + podname

		var netns1, netns2 uint64
		netns1, err = containerutils.GetNetNs(int(pid))
		if err == nil {
			netns2, err = containerutils.GetNetNs(os.Getpid())
		}
		if err == nil {
			if netns1 == netns2 {
				key = "host"
			}
		}
		log.Infof("DNS gadget: generate key %q from pod (%q %q pid:%d) (netns:%v host-netns:%v)", key, namespace, podname, pid, netns1, netns2)
		return key, err
	}

	attachContainerFunc := func(namespace, podname string, pid uint32) error {
		key, err := genKey(namespace, podname, pid)
		errMsg := ""
		if err == nil {
			err = t.tracer.Attach(key, pid, newDNSRequestCallback(key))
		}
		if err != nil {
			errMsg = err.Error()
		}
		t.resolver.PublishEvent(
			traceName,
			printEvent("attaching dns tracer", errMsg, key, "", ""),
		)
		return nil
	}

	detachContainerFunc := func(namespace, podname string, pid uint32) {
		key, err := genKey(namespace, podname, pid)

		if err == nil {
			err = t.tracer.Detach(key)
		}
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		t.resolver.PublishEvent(
			traceName,
			printEvent("detaching dns tracer", errMsg, key, "", ""),
		)
	}

	containerEventCallback := func(event pubsub.PubSubEvent) {
		switch event.Type {
		case pubsub.EVENT_TYPE_ADD_CONTAINER:
			attachContainerFunc(event.Container.Namespace, event.Container.Podname, event.Container.Pid)
		case pubsub.EVENT_TYPE_REMOVE_CONTAINER:
			detachContainerFunc(event.Container.Namespace, event.Container.Podname, event.Container.Pid)
		}
	}

	existingContainers := t.resolver.Subscribe(
		genPubSubKey(trace.ObjectMeta.Namespace+"/"+trace.ObjectMeta.Name),
		*gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		containerEventCallback,
	)

	for _, c := range existingContainers {
		err := attachContainerFunc(c.Namespace, c.Podname, c.Pid)
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
