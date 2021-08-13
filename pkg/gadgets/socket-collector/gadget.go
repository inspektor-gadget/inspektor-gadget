// Copyright 2021 The Inspektor Gadget authors
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

package socketcollector

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/tracer"
)

type Trace struct {
	resolver gadgets.Resolver
}

type TraceFactory struct {
	gadgets.BaseFactory
	mu     sync.Mutex
	traces map[string]*Trace
}

func (f *TraceFactory) LookupOrCreate(name types.NamespacedName) gadgets.Trace {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.traces == nil {
		f.traces = make(map[string]*Trace)
	}
	trace, ok := f.traces[name.String()]
	if ok {
		return trace
	}
	trace = &Trace{
		resolver: f.Resolver,
	}
	f.traces[name.String()] = trace

	return trace
}

func (f *TraceFactory) Delete(name types.NamespacedName) error {
	log.Infof("Deleting %s", name.String())
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.traces[name.String()]
	if !ok {
		log.Infof("Deleting %s: does not exist", name.String())
		return nil
	}
	delete(f.traces, name.String())
	return nil
}

func (t *Trace) Operation(trace *gadgetv1alpha1.Trace,
	operation string,
	params map[string]string) {

	if trace.ObjectMeta.Namespace != gadgets.TRACE_DEFAULT_NAMESPACE {
		gadgets.SetStatusError(trace, fmt.Sprintf("This gadget only accepts operations on traces in the %s namespace", gadgets.TRACE_DEFAULT_NAMESPACE))
		return
	}

	switch operation {
	case "start":
		var pid uint32 = 0

		if trace.Spec.Filter.Namespace == "" {
			gadgets.SetStatusError(trace, "Invalid filter: missing namespace")
			return
		}
		if trace.Spec.Filter.Podname == "" {
			gadgets.SetStatusError(trace, "TODO: Filtering only by namespace is not currently supported")
			return
		}
		if trace.Spec.Filter.Labels != nil {
			gadgets.SetStatusError(trace, "TODO: Filtering by labels is not currently supported")
			return
		}
		if trace.Spec.Filter.ContainerName != "" {
			log.Warningf("Gadget %s: Container name filter is not applicable in this gadget, ignoring it!", trace.Spec.Gadget)
		}

		pidsInPod := t.resolver.LookupPIDByPod(trace.Spec.Filter.Namespace, trace.Spec.Filter.Podname)

		// All containers inside a pod share the same network namespace
		// thus we can just take the first valid pid we found
		for _, pid = range pidsInPod {
			if pid != 0 {
				break
			}
		}

		log.Infof("Gadget %s: Using PID %d to retrieve network namespaces of Podname %q in Namespace %q",
			trace.Spec.Gadget, pid, trace.Spec.Filter.Podname, trace.Spec.Filter.Namespace)

		if pid == 0 {
			gadgets.SetStatusError(trace, fmt.Sprintf("Couldn't find a valid PID for Podname %q in Namespace %q",
				trace.Spec.Filter.Namespace, trace.Spec.Filter.Podname))
			return
		}

		t.Start(trace, pid)
	default:
		gadgets.SetStatusError(trace, fmt.Sprintf("Unknown operation %q", operation))
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace, pid uint32) {
	output, err := tracer.RunCollector(
		pid,
		trace.Spec.Filter,
	)
	if err != nil {
		gadgets.SetStatusError(trace, err.Error())
		return
	}
	trace.Status.OperationError = ""
	trace.Status.Output = output
	trace.Status.State = "Completed"
}
