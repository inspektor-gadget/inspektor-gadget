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

// Package containercollection provides the ContainerCollection struct to keep
// track of the set of running containers and primitives to query that set with
// various criteria.
//
// It is used by the Gadget Tracer Manager to keep track of containers part of
// Kubernetes pods and by IG Manager to keep track of containers on a
// Linux system.
package containercollection

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// ContainerCollection holds a set of containers. It can be embedded as an
// anonymous struct to help other structs implement the ContainerResolver
// interface. For this reason, some methods are namespaced with 'Container' to
// make this clear.
type ContainerCollection struct {
	// Keys:   containerID string
	// Values: container   Container
	containers sync.Map

	// Saves containers for "cacheDelay" to be able to enrich events after the container is
	// removed. This is enabled by using WithTracerCollection().
	cachedContainers *sync.Map
	cacheDelay       time.Duration

	// subs contains a list of subscribers of container events
	pubsub *GadgetPubSub

	// containerEnrichers are functions that automatically add metadata
	// upon AddContainer. The functions return true on success or false if
	// the container is meant to be dropped.
	containerEnrichers []func(container *Container) (ok bool)

	// initialContainers is used during the initialization process to
	// gather initial containers and then call the enrichers
	initialContainers []*Container

	// nodeName is used by the Enrich() function
	nodeName string

	// initialized tells if Initialize() has been called.
	initialized bool

	// closed tells if Close() has been called.
	closed bool

	// functions to be called on Close()
	cleanUpFuncs []func()
}

// ContainerCollectionOption are options to pass to
// Initialize using the functional option code pattern.
type ContainerCollectionOption func(*ContainerCollection) error

// Initialize initializes a ContainerCollection. It is
// useful when ContainerCollection is embedded as an anonymous struct because
// we don't use a contructor in that case.
func (cc *ContainerCollection) Initialize(options ...ContainerCollectionOption) error {
	if cc.initialized {
		panic("Initialize already called")
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

		cc.containers.Store(container.ID, container)
		if cc.pubsub != nil {
			cc.pubsub.Publish(EventTypeAddContainer, container)
		}
	}
	cc.initialContainers = nil

	cc.initialized = true
	return nil
}

// GetContainer looks up a container by the container id and return it if
// found, or return nil if not found.
func (cc *ContainerCollection) GetContainer(id string) *Container {
	v, ok := cc.containers.Load(id)
	if !ok {
		return nil
	}
	container := v.(*Container)
	return container
}

// RemoveContainer removes a container from the collection, but only after
// notifying all the subscribers.
func (cc *ContainerCollection) RemoveContainer(id string) {
	v, loaded := cc.containers.Load(id)
	if !loaded {
		return
	}

	container := v.(*Container)

	if cc.pubsub != nil {
		cc.pubsub.Publish(EventTypeRemoveContainer, container)
	}

	// Save the container in the cache as enrichers might need the container some time after it
	// has been removed.
	if cc.cachedContainers != nil {
		cc.cachedContainers.Store(id, v)
		time.AfterFunc(cc.cacheDelay, func() {
			cc.cachedContainers.Delete(id)
			unix.Close(container.mntNsFd)
		})
	}

	// Remove the container from the collection after publishing the event as
	// subscribers might need to use the different collection's lookups during
	// the notification handler, and they expect the container to still be
	// present.
	cc.containers.Delete(id)
}

// AddContainer adds a container to the collection.
func (cc *ContainerCollection) AddContainer(container *Container) {
	for _, enricher := range cc.containerEnrichers {
		ok := enricher(container)
		// Enrichers can decide to drop a container
		if !ok {
			return
		}
	}

	_, loaded := cc.containers.LoadOrStore(container.ID, container)
	if loaded {
		return
	}
	if cc.pubsub != nil {
		cc.pubsub.Publish(EventTypeAddContainer, container)
	}
}

// LookupMntnsByContainer returns the mount namespace inode of the container
// specified in arguments or zero if not found
func (cc *ContainerCollection) LookupMntnsByContainer(namespace, pod, container string) (mntns uint64) {
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*Container)
		if namespace == c.Namespace && pod == c.Podname && container == c.Name {
			mntns = c.Mntns
			// container found, stop iterating
			return false
		}
		return true
	})
	return
}

func lookupContainerByMntns(m *sync.Map, mntnsid uint64) *Container {
	var container *Container

	m.Range(func(key, value interface{}) bool {
		c := value.(*Container)
		if c.Mntns == mntnsid {
			container = c
			// container found, stop iterating
			return false
		}
		return true
	})
	return container
}

// LookupContainerByMntns returns a container by its mount namespace
// inode id. If not found nil is returned.
func (cc *ContainerCollection) LookupContainerByMntns(mntnsid uint64) *Container {
	return lookupContainerByMntns(&cc.containers, mntnsid)
}

// LookupContainersByNetns returns a slice of containers that run in a given
// network namespace. Or an empty slice if there are no containers running in
// that network namespace.
func (cc *ContainerCollection) LookupContainersByNetns(netnsid uint64) (containers []*Container) {
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*Container)
		if c.Netns == netnsid {
			containers = append(containers, c)
		}
		return true
	})
	return containers
}

// LookupMntnsByPod returns the mount namespace inodes of all containers
// belonging to the pod specified in arguments, indexed by the name of the
// containers or an empty map if not found
func (cc *ContainerCollection) LookupMntnsByPod(namespace, pod string) map[string]uint64 {
	ret := make(map[string]uint64)
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*Container)
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
		c := value.(*Container)
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
		c := value.(*Container)
		if namespace == c.Namespace && pod == c.Podname {
			ret[c.Name] = c.Pid
		}
		return true
	})
	return ret
}

// LookupOwnerReferenceByMntns returns a pointer to the owner reference of the
// container identified by the mount namespace, or nil if not found
func (cc *ContainerCollection) LookupOwnerReferenceByMntns(mntns uint64) *metav1.OwnerReference {
	var ownerRef *metav1.OwnerReference
	var err error
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*Container)
		if mntns == c.Mntns {
			ownerRef, err = c.GetOwnerReference()
			if err != nil {
				log.Warnf("Failed to get owner reference of %s/%s/%s: %s",
					c.Namespace, c.Podname, c.Name, err)
			}
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
	containerSelector *ContainerSelector,
) []*Container {
	selectedContainers := []*Container{}
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*Container)
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
func (cc *ContainerCollection) ContainerRange(f func(*Container)) {
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*Container)
		f(c)
		return true
	})
}

// ContainerRangeWithSelector iterates over the containers of the collection
// and calls the callback function for each of those that matches the container
// selector.
func (cc *ContainerCollection) ContainerRangeWithSelector(
	containerSelector *ContainerSelector,
	f func(*Container),
) {
	cc.containers.Range(func(key, value interface{}) bool {
		c := value.(*Container)
		if ContainerSelectorMatches(containerSelector, c) {
			f(c)
		}
		return true
	})
}

func (cc *ContainerCollection) EnrichNode(event *eventtypes.CommonData) {
	event.Node = cc.nodeName
}

func (cc *ContainerCollection) EnrichByMntNs(event *eventtypes.CommonData, mountnsid uint64) {
	event.Node = cc.nodeName

	container := lookupContainerByMntns(&cc.containers, mountnsid)
	if container == nil && cc.cachedContainers != nil {
		container = lookupContainerByMntns(cc.cachedContainers, mountnsid)
	}

	if container != nil {
		event.Container = container.Name
		event.Pod = container.Podname
		event.Namespace = container.Namespace
	}
}

func (cc *ContainerCollection) EnrichByNetNs(event *eventtypes.CommonData, netnsid uint64) {
	event.Node = cc.nodeName

	containers := cc.LookupContainersByNetns(netnsid)
	if len(containers) == 0 || containers[0].HostNetwork {
		return
	}
	if len(containers) == 1 {
		event.Container = containers[0].Name
		event.Pod = containers[0].Podname
		event.Namespace = containers[0].Namespace
		return
	}
	if containers[0].Podname != "" && containers[0].Namespace != "" {
		// Kubernetes containers within the same pod.
		event.Pod = containers[0].Podname
		event.Namespace = containers[0].Namespace
	}
	// else {
	// 	TODO: Non-Kubernetes containers sharing the same network namespace.
	// 	What should we do here?
	// }
}

// Subscribe returns the list of existing containers and registers a callback
// for notifications about additions and deletions of containers
func (cc *ContainerCollection) Subscribe(key interface{}, selector ContainerSelector, f FuncNotify) []*Container {
	if cc.pubsub == nil {
		panic("ContainerCollection's pubsub uninitialized")
	}
	ret := []*Container{}
	cc.pubsub.Subscribe(key, func(event PubSubEvent) {
		if ContainerSelectorMatches(&selector, event.Container) {
			f(event)
		}
	}, func() {
		// Fetch the list of containers inside pubsub.Subscribe() to
		// guarantee that no new container event will be published at
		// the same time.
		cc.ContainerRangeWithSelector(&selector, func(c *Container) {
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

func (cc *ContainerCollection) Close() {
	if !cc.initialized || cc.closed {
		panic("ContainerCollection is not initialized or has been closed")
	}

	for _, f := range cc.cleanUpFuncs {
		f()
	}

	// TODO: it's not clear if we want/can allow to re-initialize
	// this instance yet, so we don't set cc.initialized = false.
	cc.closed = true
}
