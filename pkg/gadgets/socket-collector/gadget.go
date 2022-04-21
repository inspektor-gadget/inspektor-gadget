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

	log "github.com/sirupsen/logrus"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/tracer"
	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
)

type Trace struct {
	resolver gadgets.Resolver
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{}
}

func (f *TraceFactory) Description() string {
	return `The socket-collector gadget gathers information about TCP and UDP sockets.`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status": {},
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			resolver: f.Resolver,
		}
	}

	return map[string]gadgets.TraceOperation{
		"collect": {
			Doc: "Create a snapshot of the currently open TCP and UDP sockets. " +
				"Once taken, the snapshot is not updated automatically. " +
				"However one can call the collect operation again at any time to update the snapshot.",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Collect(trace)
			},
		},
	}
}

func (t *Trace) Collect(trace *gadgetv1alpha1.Trace) {
	if trace.Spec.Filter != nil && trace.Spec.Filter.ContainerName != "" {
		log.Warningf("Gadget %s: Container name filter is not applicable in this gadget, ignoring it!",
			trace.Spec.Gadget)
	}

	selector := gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter)
	filteredContainers := t.resolver.GetContainersBySelector(selector)
	if len(filteredContainers) == 0 {
		trace.Status.OperationWarning = "No container matches the requested filter"
		trace.Status.State = "Completed"
		return
	}

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
				trace.Status.OperationError = fmt.Sprintf("aborting! The following container does not have PID %+v", container)
				return
			}

			// The stored value does not matter, we are just keeping
			// track of the visited Pods per Namespace
			visitedPods[key] = struct{}{}

			log.Debugf("Gadget %s: Using PID %d to retrieve network namespace of Pod %q in Namespace %q",
				trace.Spec.Gadget, container.Pid, container.Podname, container.Namespace)

			protocol := socketcollectortypes.ALL

			if trace.Spec.Parameters != nil {
				if val, ok := trace.Spec.Parameters["protocol"]; ok {
					var err error
					protocol, err = socketcollectortypes.ParseProtocol(val)
					if err != nil {
						trace.Status.OperationError = err.Error()
						return
					}
				}
			}

			podSockets, err := tracer.RunCollector(container.Pid, container.Podname,
				container.Namespace, trace.Spec.Node, protocol)
			if err != nil {
				trace.Status.OperationError = err.Error()
				return
			}

			allSockets = append(allSockets, podSockets...)
		}
	}

	output, err := json.MarshalIndent(allSockets, "", " ")
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed marshalling sockets: %s", err)
		return
	}

	trace.Status.Output = string(output)
	trace.Status.State = "Completed"
}
