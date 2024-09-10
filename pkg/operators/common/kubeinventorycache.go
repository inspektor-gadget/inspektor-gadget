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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/cachedmap"
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

type inventoryCache struct {
	clientset *kubernetes.Clientset

	factory informers.SharedInformerFactory

	pods     cachedmap.CachedMap[string, *v1.Pod]
	podsByIp cachedmap.CachedMap[string, *v1.Pod]
	svcs     cachedmap.CachedMap[string, *v1.Service]
	svcsByIp cachedmap.CachedMap[string, *v1.Service]

	exit chan struct{}

	useCount      int
	useCountMutex sync.Mutex
}

const (
	informerResync = 10 * time.Minute
)

var (
	k8sInventorySingleton *inventoryCache
	k8sInventoryErr       error
	k8sInventoryOnce      sync.Once
)

func GetK8sInventoryCache() (K8sInventoryCache, error) {
	k8sInventoryOnce.Do(func() {
		k8sInventorySingleton, k8sInventoryErr = newCache()
	})
	return k8sInventorySingleton, k8sInventoryErr
}

func newCache() (*inventoryCache, error) {
	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, fmt.Errorf("creating new k8s clientset: %w", err)
	}

	return &inventoryCache{
		clientset: clientset,
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
	if cache.pods != nil {
		cache.pods.Close()
		cache.pods = nil
	}
	if cache.podsByIp != nil {
		cache.podsByIp.Close()
		cache.podsByIp = nil
	}
	if cache.svcs != nil {
		cache.svcs.Close()
		cache.svcs = nil
	}
	if cache.svcsByIp != nil {
		cache.svcsByIp.Close()
		cache.svcsByIp = nil
	}
}

func (cache *inventoryCache) Start() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// No uses before us, we are the first one
	if cache.useCount == 0 {
		cache.pods = cachedmap.NewCachedMap[string, *v1.Pod](2 * time.Second)
		cache.podsByIp = cachedmap.NewCachedMap[string, *v1.Pod](2 * time.Second)
		cache.svcs = cachedmap.NewCachedMap[string, *v1.Service](2 * time.Second)
		cache.svcsByIp = cachedmap.NewCachedMap[string, *v1.Service](2 * time.Second)

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
	return cache.pods.Values()
}

func (cache *inventoryCache) GetPodByName(namespace string, name string) *v1.Pod {
	pod, found := cache.pods.Get(namespace + "/" + name)
	if !found {
		return nil
	}
	return pod
}

func (cache *inventoryCache) GetPodByIp(ip string) *v1.Pod {
	pod, found := cache.podsByIp.Get(ip)
	if !found {
		return nil
	}
	return pod
}

func (cache *inventoryCache) GetSvcs() []*v1.Service {
	return cache.svcs.Values()
}

func (cache *inventoryCache) GetSvcByName(namespace string, name string) *v1.Service {
	svc, found := cache.svcs.Get(namespace + "/" + name)
	if !found {
		return nil
	}
	return svc
}

func (cache *inventoryCache) GetSvcByIp(ip string) *v1.Service {
	svc, found := cache.svcsByIp.Get(ip)
	if !found {
		return nil
	}
	return svc
}

func (cache *inventoryCache) OnAdd(obj any, _ bool) {
	switch o := obj.(type) {
	case *v1.Pod:
		key, err := k8sCache.MetaNamespaceKeyFunc(o)
		if err != nil {
			log.Warnf("OnAdd: error getting key for pod: %v", err)
			return
		}
		cache.pods.Add(key, o)
		if ip := o.Status.PodIP; ip != "" {
			cache.podsByIp.Add(ip, o)
		}
	case *v1.Service:
		key, err := k8sCache.MetaNamespaceKeyFunc(o)
		if err != nil {
			log.Warnf("OnAdd: error getting key for service: %v", err)
			return
		}
		cache.svcs.Add(key, o)
		if ip := o.Spec.ClusterIP; ip != "" {
			cache.svcsByIp.Add(ip, o)
		}
	default:
		log.Warnf("OnAdd: unknown object type: %T", o)
	}
}

func (cache *inventoryCache) OnUpdate(_, newObj any) {
	switch o := newObj.(type) {
	case *v1.Pod:
		key, err := k8sCache.MetaNamespaceKeyFunc(o)
		if err != nil {
			log.Warnf("OnUpdate: error getting key for pod: %v", err)
			return
		}
		cache.pods.Add(key, o)
		if ip := o.Status.PodIP; ip != "" {
			cache.podsByIp.Add(ip, o)
		}
	case *v1.Service:
		key, err := k8sCache.MetaNamespaceKeyFunc(o)
		if err != nil {
			log.Warnf("OnUpdate: error getting key for service: %v", err)
			return
		}
		cache.svcs.Add(key, o)
		if ip := o.Spec.ClusterIP; ip != "" {
			cache.svcsByIp.Add(ip, o)
		}
	default:
		log.Warnf("OnUpdate: unknown object type: %T", o)
	}
}

func (cache *inventoryCache) OnDelete(obj any) {
	switch o := obj.(type) {
	case *v1.Pod:
		key, err := k8sCache.MetaNamespaceKeyFunc(o)
		if err != nil {
			log.Warnf("OnDelete: error getting key for pod: %v", err)
			return
		}
		cache.pods.Remove(key)
		if ip := o.Status.PodIP; ip != "" {
			cache.podsByIp.Remove(ip)
		}
	case *v1.Service:
		key, err := k8sCache.MetaNamespaceKeyFunc(o)
		if err != nil {
			log.Warnf("OnDelete: error getting key for service: %v", err)
			return
		}
		cache.svcs.Remove(key)
		if ip := o.Spec.ClusterIP; ip != "" {
			cache.svcsByIp.Remove(ip)
		}
	case k8sCache.DeletedFinalStateUnknown:
		cache.OnDelete(o.Obj)
	default:
		log.Warnf("OnDelete: unknown object type: %T", o)
	}
}
