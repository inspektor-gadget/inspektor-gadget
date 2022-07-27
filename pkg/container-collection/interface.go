// Copyright 2019-2022 The Inspektor Gadget authors
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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ContainerResolver offers primitives to look up running containers with
// various criteria, and to subscribe to container creation and termination.
type ContainerResolver interface {
	// LookupMntnsByContainer returns the mount namespace inode of the container
	// specified in arguments or zero if not found
	LookupMntnsByContainer(namespace, pod, container string) uint64

	// LookupContainerByMntns returns a container by its mount namespace
	// inode id. If not found nil is returned.
	LookupContainerByMntns(mntnsid uint64) *Container

	// LookupMntnsByPod returns the mount namespace inodes of all containers
	// belonging to the pod specified in arguments, indexed by the name of the
	// containers or an empty map if not found
	LookupMntnsByPod(namespace, pod string) map[string]uint64

	// LookupPIDByContainer returns the PID of the container
	// specified in arguments or zero if not found
	LookupPIDByContainer(namespace, pod, container string) uint32

	// LookupPIDByPod returns the PID of all containers belonging to
	// the pod specified in arguments, indexed by the name of the
	// containers or an empty map if not found
	LookupPIDByPod(namespace, pod string) map[string]uint32

	// LookupOwnerReferenceByMntns returns a pointer to the owner reference of the
	// container identified by the mount namespace, or nil if not found
	LookupOwnerReferenceByMntns(mntns uint64) *metav1.OwnerReference

	// GetContainersBySelector returns a slice of containers that match
	// the selector or an empty slice if there are not matches
	GetContainersBySelector(containerSelector *ContainerSelector) []*Container

	// Subscribe returns the list of existing containers and registers a
	// callback for notifications about additions and deletions of
	// containers
	Subscribe(key interface{}, s ContainerSelector, f FuncNotify) []*Container

	// Unsubscribe undoes a previous call to Subscribe
	Unsubscribe(key interface{})
}
