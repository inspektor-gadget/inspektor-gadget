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
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

// Container represents a container with its metadata.
type Container struct {
	// Container Runtime
	Runtime string `json:"runtime,omitempty" column:"runtime,minWidth:5,maxWidth:10" columnTags:"runtime"`

	// ID is the container id, typically a 64 hexadecimal string
	ID string `json:"id,omitempty" column:"id,width:13,maxWidth:64" columnTags:"runtime"`

	// Pid is the process id of the container
	Pid uint32 `json:"pid,omitempty" column:"pid,template:pid,hide"`

	// Container's configuration is the config.json from the OCI runtime
	// spec
	OciConfig *ocispec.Spec `json:"ociConfig,omitempty"`

	// Bundle is the directory containing the config.json from the OCI
	// runtime spec
	// See https://github.com/opencontainers/runtime-spec/blob/main/bundle.md
	Bundle string `json:"bundle,omitempty"`

	// Linux metadata can be derived from the pid via /proc/$pid/...
	Mntns       uint64 `json:"mntns,omitempty" column:"mntns,template:ns"`
	Netns       uint64 `json:"netns,omitempty" column:"netns,template:ns"`
	HostNetwork bool   `json:"hostNetwork,omitempty" column:"hostNetwork,width:11,fixed,hide"`
	CgroupPath  string `json:"cgroupPath,omitempty"`
	CgroupID    uint64 `json:"cgroupID,omitempty"`
	// Data required to find the container to Pod association in the
	// gadgettracermanager.
	CgroupV1 string `json:"cgroupV1,omitempty"`
	CgroupV2 string `json:"cgroupV2,omitempty"`

	// Kubernetes metadata
	Namespace string            `json:"namespace,omitempty"`
	Podname   string            `json:"podname,omitempty"`
	Name      string            `json:"name,omitempty" column:"name,width:30" columnTags:"runtime"`
	Labels    map[string]string `json:"labels,omitempty"`
	PodUID    string            `json:"podUID,omitempty"`

	ownerReference *metav1.OwnerReference

	// We keep an open file descriptor of the containers mount namespace to be sure the kernel
	// doesn't reuse the inode id before we get rid of this container. This logic avoids a race
	// condition when the mnt ns inode id is reused by a new container and we erroneously pick
	// events from it.
	// This is only used when cachedContainers are enabled through WithTracerCollection().
	mntNsFd int
}

type ContainerSelector struct {
	Namespace string
	Podname   string
	Labels    map[string]string
	Name      string
}

// GetOwnerReference returns the owner reference information of the
// container. Currently it's added to the seccomp profile as annotations
// to help users to identify the workflow of the profile. We "lazily
// enrich" this information because this operation is expensive and this
// information is only needed in some cases.
func (c *Container) GetOwnerReference() (*metav1.OwnerReference, error) {
	if c.ownerReference != nil {
		return c.ownerReference, nil
	}

	kubeconfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("couldn't get Kubernetes config: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("couldn't get dynamic Kubernetes client: %w", err)
	}

	err = ownerReferenceEnrichment(dynamicClient, c, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to enrich owner reference: %w", err)
	}

	return c.ownerReference, nil
}

func ownerReferenceEnrichment(
	dynamicClient dynamic.Interface,
	container *Container,
	ownerReferences []metav1.OwnerReference,
) error {
	resGroupVersion := "v1"
	resKind := "pods"
	resName := container.Podname
	resNamespace := container.Namespace

	var highestOwnerRef *metav1.OwnerReference

	// Iterate until we reach the highest level of reference with one of the
	// expected resource kind. Take into account that if this logic is changed,
	// the gadget cluster role needs to be updated accordingly.
	for {
		if len(ownerReferences) == 0 {
			var err error
			ownerReferences, err = getOwnerReferences(dynamicClient,
				resNamespace, resKind, resGroupVersion, resName)
			if err != nil {
				return fmt.Errorf("failed to get %s/%s/%s/%s owner reference: %w",
					resNamespace, resKind, resGroupVersion, resName, err)
			}

			// No owner reference found
			if len(ownerReferences) == 0 {
				break
			}
		}

		ownerRef := getExpectedOwnerReference(ownerReferences)
		if ownerRef == nil {
			// None expected owner reference found
			break
		}

		// Update parameters for next iteration (Namespace does not change)
		highestOwnerRef = ownerRef
		resGroupVersion = ownerRef.APIVersion
		resKind = strings.ToLower(ownerRef.Kind) + "s"
		resName = ownerRef.Name
		ownerReferences = nil
	}

	// Update container's owner reference (If any)
	if highestOwnerRef != nil {
		container.ownerReference = &metav1.OwnerReference{
			APIVersion: highestOwnerRef.APIVersion,
			Kind:       highestOwnerRef.Kind,
			Name:       highestOwnerRef.Name,
			UID:        highestOwnerRef.UID,
		}
	}

	return nil
}

func GetColumns() *columns.Columns[Container] {
	return columns.MustCreateColumns[Container]()
}

func (c *Container) IsEnriched() bool {
	return c.Name != "" && c.Podname != "" && c.Namespace != "" && c.PodUID != "" && c.Runtime != ""
}
