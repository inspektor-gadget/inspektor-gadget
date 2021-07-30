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

package processcollector

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/tracer"
)

type Trace struct {
}

type TraceFactory struct {
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
	trace = &Trace{}
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

func (t *Trace) Operation(trace *gadgetv1alpha1.Trace, resolver gadgets.Resolver, operation string, params map[string]string) {
	if trace.ObjectMeta.Namespace != gadgets.TRACE_DEFAULT_NAMESPACE {
		trace.Status.OperationError = fmt.Sprintf("This gadget only accepts operations on traces in the %s namespace", gadgets.TRACE_DEFAULT_NAMESPACE)
		return
	}
	switch operation {
	case "start":
		t.Start(trace)
	default:
		trace.Status.OperationError = fmt.Sprintf("Unknown operation %q", operation)
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	output, err := tracer.RunCollector(
		gadgets.TracePinPath(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name),
	)
	if err != nil {
		trace.Status.OperationError = err.Error()
		return
	}
	trace.Status.OperationError = ""
	trace.Status.Output = output
	trace.Status.State = "Completed"
}
