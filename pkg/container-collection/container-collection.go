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

// Package containercollection provides the ContainerCollection struct to keep
// track of the set of running containers and primitives to query that set with
// various criteria.
//
// It is used by the Gadget Tracer Manager to keep track of containers part of
// Kubernetes pods and by Local Gadget Manager to keep track of containers on a
// Linux system.
package containercollection

import (
	"sync"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
)

// ContainerCollection holds a set of containers. It can be embedded as an
// anonymous struct to help other structs implement the ContainerResolver
// interface. For this reason, some methods are namespaced with 'Container' to
// make this clear.
type ContainerCollection struct {
	// Keys:   containerID string
	// Values: container   *pb.ContainerDefinition
	containers sync.Map

	// subs contains a list of subscribers of container events
	pubsub *pubsub.GadgetPubSub

	// containerEnrichers are functions that automatically add metadata
	// upon AddContainer. The functions return true on success or false if
	// the container is meant to be dropped.
	containerEnrichers []func(container *pb.ContainerDefinition) (ok bool)

	// initialContainers is used during the initialization process to
	// gather initial containers and then call the enrichers
	initialContainers []*pb.ContainerDefinition

	// initialized tells if ContainerCollectionInitialize has been called.
	initialized bool
}

// ContainerCollectionOption are options to pass to
// ContainerCollectionInitialize using the functional option code pattern.
type ContainerCollectionOption func(*ContainerCollection) error

// ContainerCollectionInitialize initializes a ContainerCollection. It is
// useful when ContainerCollection is embedded as an anonymous struct because
// we don't use a contructor in that case.
func (cc *ContainerCollection) ContainerCollectionInitialize(options ...ContainerCollectionOption) error {
	if cc.initialized {
		panic("ContainerCollectionInitialize already called")
	}

	// Call functional options. This might fetch initial containers.
	for _, o := range options {
		err := o(cc)
		if err != nil {
			return err
		}
	}

	// Consume initial containers that might have been fetched by
	// functional options. This is done after all functional options have
	// been called, so that cc.containerEnrichers is fully set up.
initialContainersLoop:
	for _, container := range cc.initialContainers {
		for _, enricher := range cc.containerEnrichers {
			ok := enricher(container)
			if !ok {
				// Enrichers can decide to drop a container
				continue initialContainersLoop
			}
		}

		cc.containers.Store(container.Id, container)
		if cc.pubsub != nil {
			cc.pubsub.Publish(pubsub.EVENT_TYPE_ADD_CONTAINER, *container)
		}
	}
	cc.initialContainers = nil

	cc.initialized = true
	return nil
}

// GetContainer looks up a container by the container id and return it if
// found, or return nil if not found.
func (cc *ContainerCollection) GetContainer(id string) *pb.ContainerDefinition {
	v, ok := cc.containers.Load(id)
	if !ok {
		return nil
	}
	containerDefinition := v.(*pb.ContainerDefinition)
	return containerDefinition
}

// RemoveContainer removes a container from the collection.
func (cc *ContainerCollection) RemoveContainer(id string) {
	v, loaded := cc.containers.LoadAndDelete(id)
	if !loaded {
		return
	}

	cc.pubsub.Publish(pubsub.EVENT_TYPE_REMOVE_CONTAINER, *v.(*pb.ContainerDefinition))
}

// AddContainer adds a container to the collection.
func (cc *ContainerCollection) AddContainer(container *pb.ContainerDefinition) {
	for _, enricher := range cc.containerEnrichers {
		ok := enricher(container)

		// Enrichers can decide to drop a container
		if !ok {
			return
		}
	}

	_, loaded := cc.containers.LoadOrStore(container.Id, container)
	if loaded {
		return
	}
	if cc.pubsub != nil {
		cc.pubsub.Publish(pubsub.EVENT_TYPE_ADD_CONTAINER, *container)
	}
}

// LookupMntnsByContainer returns the mount namespace inode of the container
// specified in arguments or zero if not found
func (cc *ContainerCollection) LookupMntnsByContainer(namespace, pod, container string) (mntns uint64) {
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*pb.ContainerDefinition)
		if namespace == c.Namespace && pod == c.Podname && container == c.Name {
			mntns = c.Mntns
			// container found, stop iterating
			return false
		}
		return true
	})
	return
}

// LookupMntnsByPod returns the mount namespace inodes of all containers
// belonging to the pod specified in arguments, indexed by the name of the
// containers or an empty map if not found
func (cc *ContainerCollection) LookupMntnsByPod(namespace, pod string) map[string]uint64 {
	ret := make(map[string]uint64)
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*pb.ContainerDefinition)
		if namespace == c.Namespace && pod == c.Podname {
			ret[c.Name] = c.Mntns
		}
		return true
	})
	return ret
}

// LookupPIDByContainer returns the PID of the container
// specified in arguments or zero if not found
func (cc *ContainerCollection) LookupPIDByContainer(namespace, pod, container string) (pid uint32) {
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*pb.ContainerDefinition)
		if namespace == c.Namespace && pod == c.Podname && container == c.Name {
			pid = c.Pid
			// container found, stop iterating
			return false
		}
		return true
	})
	return
}

// LookupPIDByPod returns the PID of all containers belonging to
// the pod specified in arguments, indexed by the name of the
// containers or an empty map if not found
func (cc *ContainerCollection) LookupPIDByPod(namespace, pod string) map[string]uint32 {
	ret := make(map[string]uint32)
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*pb.ContainerDefinition)
		if namespace == c.Namespace && pod == c.Podname {
			ret[c.Name] = c.Pid
		}
		return true
	})
	return ret
}

// LookupOwnerReferenceByMntns returns a pointer to the owner reference of the
// container identified by the mount namespace, or nil if not found
func (cc *ContainerCollection) LookupOwnerReferenceByMntns(mntns uint64) *pb.OwnerReference {
	var ownerRef *pb.OwnerReference
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*pb.ContainerDefinition)
		if mntns == c.Mntns {
			ownerRef = c.OwnerReference
			// container found, stop iterating
			return false
		}
		return true
	})
	return ownerRef
}

// GetContainersBySelector returns a slice of containers that match
// the selector or an empty slice if there are not matches
func (cc *ContainerCollection) GetContainersBySelector(
	containerSelector *pb.ContainerSelector,
) []*pb.ContainerDefinition {
	selectedContainers := []*pb.ContainerDefinition{}
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*pb.ContainerDefinition)
		if ContainerSelectorMatches(containerSelector, c) {
			selectedContainers = append(selectedContainers, c)
		}
		return true
	})
	return selectedContainers
}

// ContainerLen returns how many containers are stored in the collection.
func (cc *ContainerCollection) ContainerLen() (count int) {
	cc.containers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return
}

// ContainerRange iterates over the containers of the collection and calls the
// callback function for each of them.
func (cc *ContainerCollection) ContainerRange(f func(*pb.ContainerDefinition)) {
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*pb.ContainerDefinition)
		f(c)
		return true
	})
}

// ContainerRangeWithSelector iterates over the containers of the collection
// and calls the callback function for each of those that matches the container
// selector.
func (cc *ContainerCollection) ContainerRangeWithSelector(
	containerSelector *pb.ContainerSelector,
	f func(*pb.ContainerDefinition),
) {
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*pb.ContainerDefinition)
		if ContainerSelectorMatches(containerSelector, c) {
			f(c)
		}
		return true
	})
}

// Subscribe returns the list of existing containers and registers a callback
// for notifications about additions and deletions of containers
func (cc *ContainerCollection) Subscribe(key interface{}, selector pb.ContainerSelector, f pubsub.FuncNotify) []*pb.ContainerDefinition {
	if cc.pubsub == nil {
		panic("ContainerCollection's pubsub uninitialized")
	}
	ret := []*pb.ContainerDefinition{}
	cc.pubsub.Subscribe(key, func(event pubsub.PubSubEvent) {
		if ContainerSelectorMatches(&selector, &event.Container) {
			f(event)
		}
	}, func() {
		// Fetch the list of containers inside pubsub.Subscribe() to
		// guarantee that no new container event will be published at
		// the same time.
		cc.ContainerRangeWithSelector(&selector, func(c *pb.ContainerDefinition) {
			ret = append(ret, c)
		})
	})
	return ret
}

// Unsubscribe undoes a previous call to Subscribe
func (cc *ContainerCollection) Unsubscribe(key interface{}) {
	if cc.pubsub == nil {
		panic("ContainerCollection's pubsub uninitialized")
	}
	cc.pubsub.Unsubscribe(key)
}
