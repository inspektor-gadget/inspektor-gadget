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
)

// Container represents a container with its metadata.
type Container struct {
	// ID is the container id, typically a 64 hexadecimal string
	ID string

	// Pid is the process id of the container
	Pid uint32

	// Container's configuration is the config.json from the OCI runtime
	// spec
	OciConfig *ocispec.Spec

	// Bundle is the directory containing the config.json from the OCI
	// runtime spec
	// See https://github.com/opencontainers/runtime-spec/blob/main/bundle.md
	Bundle string

	// Linux metadata can be derived from the pid via /proc/$pid/...
	Mntns      uint64
	Netns      uint64
	CgroupPath string
	CgroupID   uint64
	// Data required to find the container to Pod association in the
	// gadgettracermanager.
	CgroupV1 string
	CgroupV2 string

	// Kubernetes metadata
	Namespace string
	Podname   string
	Name      string
	Labels    map[string]string
	// The owner reference information is added to the seccomp profile as
	// annotations to help users to identify the workflow of the profile.
	OwnerReference *OwnerReference
	PodUID         string
}

type OwnerReference struct {
	Apiversion string
	Kind       string
	Name       string
	UID        string
}

type ContainerSelector struct {
	Namespace string
	Podname   string
	Labels    map[string]string
	Name      string
}
