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
	// containerd container annotations to get container information
	// https://github.com/containerd/containerd/blob/main/pkg/cri/annotations/annotations.go
	//
	// Pod UID annotation added in:
	// * containerd v1.7.0 via https://github.com/containerd/containerd/pull/7697
	// * containerd v1.6.11 via https://github.com/containerd/containerd/pull/7735
	containerdPodNameAnnotation       = "io.kubernetes.cri.sandbox-name"
	containerdPodNamespaceAnnotation  = "io.kubernetes.cri.sandbox-namespace"
	containerdPodUIDAnnotation        = "io.kubernetes.cri.sandbox-uid"
	containerdContainerNameAnnotation = "io.kubernetes.cri.container-name"
	containerdContainerTypeAnnotation = "io.kubernetes.cri.container-type"
)

type containerdResolver struct{}

func (containerdResolver) ContainerName(annotations map[string]string) string {
	return annotations[containerdContainerNameAnnotation]
}

func (containerdResolver) ContainerType(annotations map[string]string) string {
	return annotations[containerdContainerTypeAnnotation]
}

func (containerdResolver) PodName(annotations map[string]string) string {
	return annotations[containerdPodNameAnnotation]
}

func (containerdResolver) PodUID(annotations map[string]string) string {
	return annotations[containerdPodUIDAnnotation]
}

func (containerdResolver) PodNamespace(annotations map[string]string) string {
	return annotations[containerdPodNamespaceAnnotation]
}

func (containerdResolver) Runtime() string {
	return "containerd"
}
