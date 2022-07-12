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

package gadgets

import (
	"sync"

	"github.com/cilium/ebpf"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"

	log "github.com/sirupsen/logrus"
	apimachineryruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type TraceFactory interface {
	// Initialize gives the Resolver and the Client to the gadget. Gadgets
	// don't need to implement this method if they use BaseFactory as an
	// anonymous field.
	Initialize(Resolver Resolver, Client client.Client)

	// Delete request a gadget to release the information it has about a
	// trace. BaseFactory implements this method, so gadgets who embed
	// BaseFactory don't need to implement it.
	Delete(name string)

	// Operations gives the list of operations on a gadget that users can
	// call via the gadget.kinvolk.io/operation annotation.
	Operations() map[string]TraceOperation

	// OutputModesSupported returns the set of OutputMode supported by the
	// gadget.
	OutputModesSupported() map[string]struct{}
}

type TraceFactoryWithScheme interface {
	TraceFactory

	// AddToScheme let gadgets inform the Trace controller of any scheme
	// they want to use
	AddToScheme(*apimachineryruntime.Scheme)
}

type TraceFactoryWithDocumentation interface {
	Description() string
}

// TraceOperation packages an operation on a gadget that users can call via the
// annotation gadget.kinvolk.io/operation.
type TraceOperation struct {
	// Operation is the function called by the controller
	Operation func(name string, trace *gadgetv1alpha1.Trace)

	// Doc documents the operation. It is used to generate the
	// documentation.
	Doc string

	// Order controls the ordering of the operation in the documentation.
	// It's only needed when ordering alphabetically is not suitable.
	Order int
}

type Resolver interface {
	containercollection.ContainerResolver

	PublishEvent(tracerID string, line string) error
	TracerMountNsMap(tracerID string) (*ebpf.Map, error)
	ContainersMap() *ebpf.Map
}

type BaseFactory struct {
	Resolver Resolver
	Client   client.Client

	// DeleteTrace is optionally set by gadgets if they need to do
	// specialised clean up. Example:
	//
	// func NewFactory() gadgets.TraceFactory {
	// 	return &TraceFactory{
	// 		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	// 	}
	// }
	DeleteTrace func(name string, trace interface{})

	mu     sync.Mutex
	traces map[string]interface{}
}

func (f *BaseFactory) Initialize(r Resolver, c client.Client) {
	f.Resolver = r
	f.Client = c
}

func (f *BaseFactory) LookupOrCreate(name string, newTrace func() interface{}) interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.traces == nil {
		f.traces = make(map[string]interface{})
	} else {
		trace, ok := f.traces[name]
		if ok {
			return trace
		}
	}

	if newTrace == nil {
		return nil
	}

	trace := newTrace()
	f.traces[name] = trace

	return trace
}

func (f *BaseFactory) Delete(name string) {
	log.Infof("Deleting %s", name)
	f.mu.Lock()
	defer f.mu.Unlock()
	trace, ok := f.traces[name]
	if !ok {
		log.Infof("Deleting %s: does not exist", name)
		return
	}
	if f.DeleteTrace != nil {
		f.DeleteTrace(name, trace)
	}
	delete(f.traces, name)
}

func (f *BaseFactory) Operations() map[string]TraceOperation {
	return map[string]TraceOperation{}
}

func (f *BaseFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{}
}
