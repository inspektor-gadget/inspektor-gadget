// Copyright 2023-2024 The Inspektor Gadget authors
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

package common

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	k8sCache "k8s.io/client-go/tools/cache"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

// K8sInventoryCache is a cache of Kubernetes resources such as pods and services
// that can be used by operators to enrich events.
type K8sInventoryCache interface {
	Start()
	Stop()

	GetPods() []*v1.Pod
	GetPodByName(namespace string, name string) *v1.Pod
	GetPodByIp(ip string) *v1.Pod

	GetSvcs() []*v1.Service
	GetSvcByName(namespace string, name string) *v1.Service
	GetSvcByIp(ip string) *v1.Service
}

type oldResource[T any] struct {
	deletionTimestamp time.Time
	obj               T
}

type resourceCache[T any] struct {
	sync.Mutex
	current map[string]*T
	old     map[string]oldResource[*T]
}

func newResourceCache[T any]() *resourceCache[T] {
	return &resourceCache[T]{current: make(map[string]*T), old: make(map[string]oldResource[*T])}
}

func (c *resourceCache[T]) Add(obj *T) {
	key, err := k8sCache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		log.Warnf("resourceCache: add resource: %v", err)
		return
	}
	c.Lock()
	defer c.Unlock()
	c.current[key] = obj
	delete(c.old, key)
}

func (c *resourceCache[T]) Remove(obj *T) {
	key, err := k8sCache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		log.Warnf("resourceCache: remove resource: %v", err)
		return
	}
	c.Lock()
	defer c.Unlock()
	delete(c.current, key)
	c.old[key] = oldResource[*T]{deletionTimestamp: time.Now(), obj: obj}
}

func (c *resourceCache[T]) PruneOldObjects() {
	c.Lock()
	defer c.Unlock()
	now := time.Now()
	for key, oldObj := range c.old {
		if now.Sub(oldObj.deletionTimestamp) > oldObjectTTL {
			delete(c.old, key)
		}
	}
}

func (c *resourceCache[T]) ToSlice() []*T {
	c.PruneOldObjects()
	c.Lock()
	defer c.Unlock()

	objs := make([]*T, 0, len(c.current)+len(c.old))
	for _, obj := range c.current {
		objs = append(objs, obj)
	}
	for key, oldObj := range c.old {
		if _, ok := c.current[key]; !ok {
			objs = append(objs, oldObj.obj)
		}
	}
	return objs
}

func (c *resourceCache[T]) Get(key string) *T {
	c.PruneOldObjects()
	c.Lock()
	defer c.Unlock()

	if obj, ok := c.current[key]; ok {
		return obj
	}
	if oldObj, ok := c.old[key]; ok {
		return oldObj.obj
	}
	return nil
}

func (c *resourceCache[T]) GetCmp(cmp func(*T) bool) *T {
	c.PruneOldObjects()
	c.Lock()
	defer c.Unlock()

	for _, obj := range c.current {
		if cmp(obj) {
			return obj
		}
	}
	for _, oldObj := range c.old {
		if cmp(oldObj.obj) {
			return oldObj.obj
		}
	}
	return nil
}

type inventoryCache struct {
	clientset *kubernetes.Clientset

	factory informers.SharedInformerFactory

	pods *resourceCache[v1.Pod]
	svcs *resourceCache[v1.Service]

	exit chan struct{}

	useCount      int
	useCountMutex sync.Mutex
}

const (
	informerResync = 10 * time.Minute
	oldObjectTTL   = 2 * time.Second
)

var (
	cache *inventoryCache
	err   error
	once  sync.Once
)

func GetK8sInventoryCache() (K8sInventoryCache, error) {
	once.Do(func() {
		cache, err = newCache()
	})
	return cache, err
}

func newCache() (*inventoryCache, error) {
	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, fmt.Errorf("creating new k8s clientset: %w", err)
	}

	return &inventoryCache{
		clientset: clientset,
		pods:      newResourceCache[v1.Pod](),
		svcs:      newResourceCache[v1.Service](),
	}, nil
}

func (cache *inventoryCache) Close() {
	if cache.exit != nil {
		close(cache.exit)
		cache.exit = nil
	}
	if cache.factory != nil {
		cache.factory.Shutdown()
		cache.factory = nil
	}
}

func (cache *inventoryCache) Start() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// No uses before us, we are the first one
	if cache.useCount == 0 {
		cache.factory = informers.NewSharedInformerFactory(cache.clientset, informerResync)
		cache.factory.Core().V1().Pods().Informer().AddEventHandler(cache)
		cache.factory.Core().V1().Services().Informer().AddEventHandler(cache)

		cache.exit = make(chan struct{})
		cache.factory.Start(cache.exit)
		cache.factory.WaitForCacheSync(cache.exit)
	}
	cache.useCount++
}

func (cache *inventoryCache) Stop() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// We are the last user, stop everything
	if cache.useCount == 1 {
		cache.Close()
	}
	cache.useCount--
}

func (cache *inventoryCache) GetPods() []*v1.Pod {
	return cache.pods.ToSlice()
}

func (cache *inventoryCache) GetPodByName(namespace string, name string) *v1.Pod {
	return cache.pods.Get(namespace + "/" + name)
}

func (cache *inventoryCache) GetPodByIp(ip string) *v1.Pod {
	return cache.pods.GetCmp(func(pod *v1.Pod) bool {
		return pod.Status.PodIP == ip
	})
}

func (cache *inventoryCache) GetSvcs() []*v1.Service {
	return cache.svcs.ToSlice()
}

func (cache *inventoryCache) GetSvcByName(namespace string, name string) *v1.Service {
	return cache.svcs.Get(namespace + "/" + name)
}

func (cache *inventoryCache) GetSvcByIp(ip string) *v1.Service {
	return cache.svcs.GetCmp(func(svc *v1.Service) bool {
		return svc.Spec.ClusterIP == ip
	})
}

func (cache *inventoryCache) OnAdd(obj any, _ bool) {
	switch o := obj.(type) {
	case *v1.Pod:
		cache.pods.Add(o)
	case *v1.Service:
		cache.svcs.Add(o)
	default:
		log.Warnf("OnAdd: unknown object type: %T", o)
	}
}

func (cache *inventoryCache) OnUpdate(_, newObj any) {
	switch o := newObj.(type) {
	case *v1.Pod:
		cache.pods.Add(o)
	case *v1.Service:
		cache.svcs.Add(o)
	default:
		log.Warnf("OnUpdate: unknown object type: %T", o)
	}
}

func (cache *inventoryCache) OnDelete(obj any) {
	switch o := obj.(type) {
	case *v1.Pod:
		cache.pods.Remove(o)
	case *v1.Service:
		cache.svcs.Remove(o)
	case k8sCache.DeletedFinalStateUnknown:
		cache.OnDelete(o.Obj)
	default:
		log.Warnf("OnDelete: unknown object type: %T", o)
	}
}
