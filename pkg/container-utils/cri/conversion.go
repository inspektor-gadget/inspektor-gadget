/*
Copyright 2021 The Kubernetes Authors.
Copyright 2023 The Inspektor Gadget authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* See:
 * https://github.com/kubernetes/kubernetes/blob/v1.25.9/pkg/kubelet/cri/remote/conversion.go
 */

package cri

import (
	"unsafe"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/inspektor-gadget/inspektor-gadget/internal/thirdparty/k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

func fromV1alpha2ListContainersResponse(from *v1alpha2.ListContainersResponse) *runtimeapi.ListContainersResponse {
	return (*runtimeapi.ListContainersResponse)(unsafe.Pointer(from))
}

func fromV1alpha2ContainerStatusResponse(from *v1alpha2.ContainerStatusResponse) *runtimeapi.ContainerStatusResponse {
	return (*runtimeapi.ContainerStatusResponse)(unsafe.Pointer(from))
}

func v1alpha2ContainerFilter(from *runtimeapi.ContainerFilter) *v1alpha2.ContainerFilter {
	return (*v1alpha2.ContainerFilter)(unsafe.Pointer(from))
}
