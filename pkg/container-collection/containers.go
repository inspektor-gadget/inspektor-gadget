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
	"time"

	"github.com/moby/moby/pkg/stringid"
	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// Container represents a container with its metadata.
type Container struct {
	// Runtime contains the metadata of the container runtime
	Runtime RuntimeMetadata `json:"runtime,omitempty" column:"runtime" columnTags:"runtime"`

	// K8s contains the Kubernetes metadata of the container.
	K8s K8sMetadata `json:"k8s,omitempty" column:"k8s" columnTags:"kubernetes"`

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

	// We keep an open file descriptor of the containers mount and net namespaces to be sure the
	// kernel doesn't reuse the inode id before we get rid of this container. This logic avoids
	// a race condition when the ns inode id is reused by a new container and we erroneously
	// pick events from it or enrich data using it.
	// These are only used when cachedContainers are enabled through WithTracerCollection().
	mntNsFd int
	netNsFd int

	// when the container was removed. Useful for running cached containers.
	deletionTimestamp time.Time
}

// close releases any resources (like  file descriptors) the container is using.
func (c *Container) close() {
	if c.mntNsFd != 0 {
		unix.Close(c.mntNsFd)
		c.mntNsFd = 0
	}
	if c.netNsFd != 0 {
		unix.Close(c.netNsFd)
		c.netNsFd = 0
	}
}

type RuntimeMetadata struct {
	types.BasicRuntimeMetadata `json:",inline"`
}

type K8sMetadata struct {
	types.BasicK8sMetadata `json:",inline"`
	PodLabels              map[string]string `json:"podLabels,omitempty"`
	PodUID                 string            `json:"podUID,omitempty"`

	ownerReference *metav1.OwnerReference
}

type K8sSelector struct {
	types.BasicK8sMetadata
	PodLabels map[string]string
}

type RuntimeSelector struct {
	// TODO: Support filtering by all the fields in BasicRuntimeMetadata
	ContainerName string
}

type ContainerSelector struct {
	K8s     K8sSelector
	Runtime RuntimeSelector
}

// GetOwnerReference returns the owner reference information of the
// container. Currently it's added to the seccomp profile as annotations
// to help users to identify the workflow of the profile. We "lazily
// enrich" this information because this operation is expensive and this
// information is only needed in some cases.
func (c *Container) GetOwnerReference() (*metav1.OwnerReference, error) {
	if c.K8s.ownerReference != nil {
		return c.K8s.ownerReference, nil
	}

	kubeconfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("getting Kubernetes config: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("getting get dynamic Kubernetes client: %w", err)
	}

	err = ownerReferenceEnrichment(dynamicClient, c, nil)
	if err != nil {
		return nil, fmt.Errorf("enriching owner reference: %w", err)
	}

	return c.K8s.ownerReference, nil
}

func ownerReferenceEnrichment(
	dynamicClient dynamic.Interface,
	container *Container,
	ownerReferences []metav1.OwnerReference,
) error {
	resGroupVersion := "v1"
	resKind := "pods"
	resName := container.K8s.PodName
	resNamespace := container.K8s.Namespace

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
				return fmt.Errorf("getting %s/%s/%s/%s owner reference: %w",
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
		container.K8s.ownerReference = &metav1.OwnerReference{
			APIVersion: highestOwnerRef.APIVersion,
			Kind:       highestOwnerRef.Kind,
			Name:       highestOwnerRef.Name,
			UID:        highestOwnerRef.UID,
		}
	}

	return nil
}

func GetColumns() *columns.Columns[Container] {
	cols := columns.MustCreateColumns[Container]()

	cols.MustSetExtractor("runtime.containerImageName", func(container *Container) any {
		if container == nil {
			return ""
		}
		if strings.Contains(container.Runtime.ContainerImageName, "sha256") {
			return stringid.TruncateID(container.Runtime.ContainerImageName)
		}
		return container.Runtime.ContainerImageName
	})

	return cols
}
