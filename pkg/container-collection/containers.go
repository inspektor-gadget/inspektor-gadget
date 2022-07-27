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

package containercollection

import (
	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Container represents a container with its metadata.
type Container struct {
	// ID is the container id, typically a 64 hexadecimal string
	ID string `json:"id,omitempty"`

	// Pid is the process id of the container
	Pid uint32 `json:"pid,omitempty"`

	// Container's configuration is the config.json from the OCI runtime
	// spec
	OciConfig *ocispec.Spec `json:"ociConfig,omitempty"`

	// Bundle is the directory containing the config.json from the OCI
	// runtime spec
	// See https://github.com/opencontainers/runtime-spec/blob/main/bundle.md
	Bundle string `json:"bundle,omitempty"`

	// Linux metadata can be derived from the pid via /proc/$pid/...
	Mntns      uint64 `json:"mntns,omitempty"`
	Netns      uint64 `json:"netns,omitempty"`
	CgroupPath string `json:"cgroupPath,omitempty"`
	CgroupID   uint64 `json:"cgroupID,omitempty"`
	// Data required to find the container to Pod association in the
	// gadgettracermanager.
	CgroupV1 string `json:"cgroupV1,omitempty"`
	CgroupV2 string `json:"cgroupV2,omitempty"`

	// Kubernetes metadata
	Namespace string            `json:"namespace,omitempty"`
	Podname   string            `json:"podname,omitempty"`
	Name      string            `json:"name,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	// The owner reference information is added to the seccomp profile as
	// annotations to help users to identify the workflow of the profile.
	OwnerReference *metav1.OwnerReference `json:"ownerReference,omitempty"`
	PodUID         string                 `json:"podUID,omitempty"`

	// Container Runtime metadata
	Runtime string `json:"runtime,omitempty"`
}

type ContainerSelector struct {
	Namespace string
	Podname   string
	Labels    map[string]string
	Name      string
}
