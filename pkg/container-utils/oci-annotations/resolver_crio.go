// Copyright 2022 The Inspektor Gadget authors
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

package ociannotations

const (
	// cri-o container annotations to get container information
	// https://github.com/containers/podman/blob/main/pkg/annotations/annotations.go
	// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/types/labels.go
	crioContainerManagerAnnotation = "io.container.manager"
	crioPodNameAnnotation          = "io.kubernetes.pod.name"
	crioPodNamespaceAnnotation     = "io.kubernetes.pod.namespace"
	crioPodUIDAnnotation           = "io.kubernetes.pod.uid"
	crioContainerNameAnnotation    = "io.kubernetes.container.name"
	crioContainerTypeAnnotation    = "io.kubernetes.cri-o.ContainerType"
)

type crioResolver struct{}

func (crioResolver) ContainerName(annotations map[string]string) string {
	return annotations[crioContainerNameAnnotation]
}

func (crioResolver) ContainerType(annotations map[string]string) string {
	return annotations[crioContainerTypeAnnotation]
}

func (crioResolver) PodName(annotations map[string]string) string {
	return annotations[crioPodNameAnnotation]
}

func (crioResolver) PodUID(annotations map[string]string) string {
	return annotations[crioPodUIDAnnotation]
}

func (crioResolver) PodNamespace(annotations map[string]string) string {
	return annotations[crioPodNamespaceAnnotation]
}

func (crioResolver) Runtime() string {
	return "cri-o"
}
