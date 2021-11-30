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

package tracepkt

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netns"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	tracepkttracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/tracepkt/tracer"
	tracepkttypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/tracepkt/types"
)

type Trace struct {
	resolver  gadgets.Resolver
	traceName string
	tracer    *tracepkttracer.Tracer
	started   bool
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
	return `The tracepkt gadget`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Stream": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.tracer.Close()
		trace.tracer = nil
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			resolver: f.Resolver,
		}
	}
	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start monitoring packets",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
			Order: 1,
		},
		"add-trace": {
			Doc: "Add a TRACE rule",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).AddTrace(trace)
			},
			Order: 2,
		},
		"remove-trace": {
			Doc: "Remove a TRACE rule",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).RemoveTrace(trace)
			},
			Order: 2,
		},
		"stop": {
			Doc: "Stop monitoring packets",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
			Order: 3,
		},
	}
}

func netnsEnter(pid int, f func() error) error {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	netnsHandle, err := netns.GetFromPid(pid)
	if err != nil {
		return err
	}
	defer netnsHandle.Close()
	err = netns.Set(netnsHandle)
	if err != nil {
		return err
	}

	// Switch back to the original namespace
	defer netns.Set(origns)

	return f()
}

func (t *Trace) eventCallback(event *tracepkttypes.Event) {
	netnsId := event.NetnsIn
	if netnsId == 0 {
		netnsId = event.NetnsOut
	}
	_, host, namespace, podname := t.resolver.LookupPodByNetns(netnsId)
	event.Host = host
	event.Namespace = namespace
	event.Pod = podname

	if host {
		t.tracer.EnrichEvent(event)
	} else {
		pids := t.resolver.LookupPIDByPod(namespace, podname)
		pid := 0
		for _, p := range pids {
			pid = int(p)
			break
		}
		if pid != 0 {
			netnsEnter(pid, func() error {
				t.tracer.EnrichEvent(event)
				return nil
			})
		}
	}

	eventStr := ""
	b, e := json.Marshal(event)
	if e != nil {
		eventStr = `{"err": "cannot marshal event"}`
	}
	eventStr = string(b)

	t.resolver.PublishEvent(
		t.traceName,
		eventStr,
	)
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.OperationError = ""
		trace.Status.Output = ""
		trace.Status.State = "Started"
		return
	}

	t.traceName = gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	var err error
	t.tracer, err = tracepkttracer.NewTracer(trace.Spec.Node, t.eventCallback)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start seccomp tracer: %s", err)
		return
	}

	t.started = true

	if trace.Spec.Filter != nil && trace.Spec.Filter.Namespace != "" && trace.Spec.Filter.Podname != "" {
		t.addTrace(trace)
		return
	}

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

	t.tracer.Close()
	t.tracer = nil
	t.started = false

	trace.Status.State = "Stopped"
	return
}

func (t *Trace) AddTrace(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	if trace.Spec.Filter == nil || trace.Spec.Filter.Namespace == "" || trace.Spec.Filter.Podname == "" {
		trace.Status.OperationError = "Missing pod"
		return
	}

	t.addTrace(trace)
}

func iptablesCommentFromTrace(trace *gadgetv1alpha1.Trace) string {
	comment := fmt.Sprintf("IG-Trace=%s/%s", trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	// iptables only allow 256 characters
	if len(comment) > 256 {
		comment = comment[0:256]
	}
	return comment
}

func (t *Trace) addTrace(trace *gadgetv1alpha1.Trace) {
	selector := gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter)
	filteredContainers := t.resolver.GetContainersBySelector(selector)
	pidsByLink := map[string]uint32{}
	for _, c := range filteredContainers {
		if c.VethPeerName != "" {
			pidsByLink[c.VethPeerName] = c.Pid
		}
	}

	ipt, err := iptables.New()
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}

	// TRACE rule on the host netns
	// Catch ingress traffic to the pod
	pid := 0
	for vethPeerName, p := range pidsByLink {
		err = ipt.Append(
			"raw", "PREROUTING",
			"-i", vethPeerName,
			"-p", "tcp", "--syn",
			"-m", "comment", "--comment", iptablesCommentFromTrace(trace),
			"-j", "TRACE",
		)
		if err != nil {
			trace.Status.OperationError = err.Error()
			return
		}
		pid = int(p)
	}
	if pid == 0 {
		trace.Status.OperationError = "no pod found"
		return
	}

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	netnsHandle, err := netns.GetFromPid(pid)
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}
	defer netnsHandle.Close()
	err = netns.Set(netnsHandle)
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}

	// Switch back to the original namespace
	defer netns.Set(origns)

	// TRACE rule on the pod netns
	// Catch egress traffic to the pod
	err = ipt.Append(
		"raw", "OUTPUT",
		"-p", "tcp", "--syn",
		"-m", "comment", "--comment", iptablesCommentFromTrace(trace),
		"-j", "TRACE",
	)
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}

	trace.Status.OperationError = ""
	trace.Status.Output = ""
	trace.Status.State = "Started"
}

func (t *Trace) RemoveTrace(trace *gadgetv1alpha1.Trace) {
	trace.Status.OperationError = "RemoveTrace not implemented"
}
