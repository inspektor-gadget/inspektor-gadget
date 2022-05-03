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
	"github.com/cilium/ebpf/link"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"k8s.io/apimachinery/pkg/types"
)

const (
	PinPath = "/sys/fs/bpf/gadget"

	// The Trace custom resource is preferably in the "gadget" namespace
	TraceDefaultNamespace = "gadget"

	PerfBufferPages = 64
)

func TraceName(namespace, name string) string {
	return "trace_" + namespace + "_" + name
}

func TraceNameFromNamespacedName(n types.NamespacedName) string {
	return TraceName(n.Namespace, n.Name)
}

func ContainerSelectorFromContainerFilter(f *gadgetv1alpha1.ContainerFilter) *pb.ContainerSelector {
	if f == nil {
		return &pb.ContainerSelector{}
	}
	labels := []*pb.Label{}
	for k, v := range f.Labels {
		labels = append(labels, &pb.Label{Key: k, Value: v})
	}
	return &pb.ContainerSelector{
		Namespace: f.Namespace,
		Podname:   f.Podname,
		Labels:    labels,
		Name:      f.ContainerName,
	}
}

// CloseLink closes l if it's not nil and returns nil
func CloseLink(l link.Link) link.Link {
	if l != nil {
		l.Close()
	}
	return nil
}
