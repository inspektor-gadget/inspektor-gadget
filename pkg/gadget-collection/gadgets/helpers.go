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
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"k8s.io/apimachinery/pkg/types"
)

func TraceName(namespace, name string) string {
	return "trace_" + namespace + "_" + name
}

func TraceNameFromNamespacedName(n types.NamespacedName) string {
	return TraceName(n.Namespace, n.Name)
}

func ContainerSelectorFromContainerFilter(f *gadgetv1alpha1.ContainerFilter) *containercollection.ContainerSelector {
	if f == nil {
		return &containercollection.ContainerSelector{}
	}
	labels := map[string]string{}
	for k, v := range f.Labels {
		labels[k] = v
	}
	return &containercollection.ContainerSelector{
		Namespace: f.Namespace,
		Podname:   f.Podname,
		Labels:    labels,
		Name:      f.ContainerName,
	}
}
