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

import "errors"

// ErrUnsupportedContainerRuntime is used for unsupported container runtime
var ErrUnsupportedContainerRuntime = errors.New("unsupported container runtime")

// Resolver is used to resolve attributes for a container
// by using container runtime annotations
type Resolver interface {
	// ContainerName returns the name of the container in a pod
	ContainerName(annotations map[string]string) string
	// ContainerType returns the type of the container i.e "container" or "sandbox"
	ContainerType(annotations map[string]string) string
	// PodName returns the name of the pod to which the container belongs
	PodName(annotations map[string]string) string
	// PodUID returns the uid of pod to which the container belongs
	PodUID(annotations map[string]string) string
	// PodNamespace returns the namespace of the pod to which container belongs
	PodNamespace(annotations map[string]string) string
	// Runtime returns runtime in which the container is running
	Runtime() string
}

// NewResolver creates a Resolver for a given container runtime
func NewResolver(runtime string) (Resolver, error) {
	switch runtime {
	case "cri-o":
		return crioResolver{}, nil
	case "containerd":
		return containerdResolver{}, nil
	}
	return nil, ErrUnsupportedContainerRuntime
}

// NewResolverFromAnnotations creates a Resolver by detecting runtime from annotations
func NewResolverFromAnnotations(annotations map[string]string) (Resolver, error) {
	if cm := annotations[crioContainerManagerAnnotation]; cm == "cri-o" {
		return crioResolver{}, nil
	}
	if _, isContainerd := annotations[containerdContainerTypeAnnotation]; isContainerd {
		return containerdResolver{}, nil
	}

	return nil, ErrUnsupportedContainerRuntime
}
