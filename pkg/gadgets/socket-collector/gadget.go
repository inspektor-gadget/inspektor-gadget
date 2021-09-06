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
	"encoding/json"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/tracer"
	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

type Trace struct {
	resolver gadgets.Resolver
}

type TraceFactory struct {
	gadgets.BaseFactory
	mu     sync.Mutex
	traces map[string]*Trace
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{}
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
		gadgets.SetStatusError(trace, fmt.Sprintf("This gadget only accepts operations on traces in the %s namespace",
			gadgets.TRACE_DEFAULT_NAMESPACE))
		return
	}

	switch operation {
	case "start":
		if trace.Spec.Filter != nil && trace.Spec.Filter.ContainerName != "" {
			log.Warningf("Gadget %s: Container name filter is not applicable in this gadget, ignoring it!",
				trace.Spec.Gadget)
		}

		selector := gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter)
		filteredContainers := t.resolver.GetContainersBySelector(selector)
		if len(filteredContainers) == 0 {
			log.Warningf("No container matches the requested filter: %+v", *trace.Spec.Filter)

			trace.Status.OperationError = ""
			trace.Status.Output = ""
			trace.Status.State = "Completed"
			return
		}

		output, err := start(trace.Spec.Gadget, trace.Spec.Node, filteredContainers)
		if err != nil {
			gadgets.SetStatusError(trace, err.Error())
			return
		}

		trace.Status.OperationError = ""
		trace.Status.Output = output
		trace.Status.State = "Completed"
	default:
		gadgets.SetStatusError(trace, fmt.Sprintf("Unknown operation %q", operation))
	}
}

func start(gadgetName, node string, filteredContainers []pb.ContainerDefinition) (string, error) {
	allSockets := []socketcollectortypes.Event{}

	// Given that the socket-collector tracer works per network namespace and
	// all the containers inside a namespace/pod share the network namespace,
	// we only need to run the tracer with one valid PID per namespace/pod
	visitedPods := make(map[string]struct{})

	for _, container := range filteredContainers {
		key := container.Namespace + "/" + container.Podname
		if _, ok := visitedPods[key]; !ok {
			// Make the whole gadget fail if there is a container without PID
			// because it would be an inconsistency that has to be notified
			if container.Pid == 0 {
				return "", fmt.Errorf("aborting! The following container does not have PID %+v", container)
			}

			// The stored value does not matter, we are just keeping
			// track of the visited Pods per Namespace
			visitedPods[key] = struct{}{}

			log.Debugf("Gadget %s: Using PID %d to retrieve network namespace of Pod %q in Namespace %q",
				gadgetName, container.Pid, container.Podname, container.Namespace)

			podSockets, err := tracer.RunCollector(container.Pid, container.Podname,
				container.Namespace, node)
			if err != nil {
				return "", err
			}

			allSockets = append(allSockets, podSockets...)
		}
	}

	output, err := json.MarshalIndent(allSockets, "", " ")
	if err != nil {
		return "", fmt.Errorf("failed marshalling sockets: %w", err)
	}

	return string(output), nil
}
