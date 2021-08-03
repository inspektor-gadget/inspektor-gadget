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
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	apimachineryruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Trace interface {
	Operation(trace *gadgetv1alpha1.Trace,
		operation string,
		params map[string]string)
}

type TraceFactory interface {
	// Initialize gives the Resolver and the Client to the gadget. Gadgets
	// don't need to implement this method if they use BaseFactory as an
	// anonymous field.
	Initialize(Resolver Resolver, Client client.Client)

	// LookupOrCreate returns either an existing Trace or a new Trace for
	// the specified name
	LookupOrCreate(name types.NamespacedName) Trace

	// Delete request a gadget to release the information it has about a
	// trace. The Trace controller will requeue in case of error.
	Delete(name types.NamespacedName) error
}

type TraceFactoryWithScheme interface {
	TraceFactory

	// AddToScheme let gadgets inform the Trace controller of any scheme
	// they want to use
	AddToScheme(*apimachineryruntime.Scheme)
}

type TraceFactoryWithCapabilities interface {
	TraceFactory

	// SupportsOutputMode tells if the OutputMode is supported. If the
	// interface is not implemented, only "Status" is supported.
	SupportsOutputMode(string) bool
}

type Resolver interface {
	// LookupMntnsByContainer returns the mount namespace inode of the container
	// specified in arguments or zero if not found
	LookupMntnsByContainer(namespace, pod, container string) uint64

	// LookupMntnsByPod returns the mount namespace inodes of all containers
	// belonging to the pod specified in arguments, indexed by the name of the
	// containers
	LookupMntnsByPod(namespace, pod string) map[string]uint64
}

type BaseFactory struct {
	Resolver Resolver
	Client   client.Client
}

func (f *BaseFactory) Initialize(r Resolver, c client.Client) {
	f.Resolver = r
	f.Client = c
}
