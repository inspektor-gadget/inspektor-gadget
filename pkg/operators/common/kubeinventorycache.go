// Copyright 2023 The Inspektor Gadget authors
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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

type oldResource[T any] struct {
	deletionTimestamp time.Time
	obj               T
}

// K8sInventoryCache is a cache of Kubernetes resources such as pods and services
// that can be used by operators to enrich events.
type K8sInventoryCache struct {
	clientset *kubernetes.Clientset

	factory informers.SharedInformerFactory

	// key namespace/name
	// value *v1.Pod
	pods sync.Map
	// key namespace/name
	// value oldResource[*v1.Pod]
	oldPods sync.Map

	// key namespace/name
	// value *v1.Service
	svcs sync.Map
	// key namespace/name
	// value oldResource[*v1.Service]
	oldSvcs sync.Map

	exit chan struct{}

	useCount      int
	useCountMutex sync.Mutex
}

const (
	informerResync = 10 * time.Minute
	oldObjectTTL   = 2 * time.Second
)

var (
	cache *K8sInventoryCache
	err   error
	once  sync.Once
)

func GetK8sInventoryCache() (*K8sInventoryCache, error) {
	once.Do(func() {
		cache, err = newCache()
	})
	return cache, err
}

func newCache() (*K8sInventoryCache, error) {
	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, fmt.Errorf("creating new k8s clientset: %w", err)
	}

	return &K8sInventoryCache{
		clientset: clientset,
	}, nil
}

func (cache *K8sInventoryCache) Close() {
	if cache.exit != nil {
		close(cache.exit)
		cache.exit = nil
	}
	if cache.factory != nil {
		cache.factory.Shutdown()
		cache.factory = nil
	}
}

func (cache *K8sInventoryCache) Start() {
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

func (cache *K8sInventoryCache) Stop() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// We are the last user, stop everything
	if cache.useCount == 1 {
		cache.Close()
	}
	cache.useCount--
}

func (cache *K8sInventoryCache) removeOldPods() {
	now := time.Now()
	cache.oldPods.Range(func(key, value any) bool {
		if now.Sub(value.(oldResource[*v1.Pod]).deletionTimestamp) > oldObjectTTL {
			cache.oldPods.Delete(key)
		}
		return true
	})
}

func (cache *K8sInventoryCache) removeOldSvcs() {
	now := time.Now()
	cache.oldSvcs.Range(func(key, value any) bool {
		if now.Sub(value.(oldResource[*v1.Service]).deletionTimestamp) > oldObjectTTL {
			cache.oldSvcs.Delete(key)
		}
		return true
	})
}

func (cache *K8sInventoryCache) GetPods() ([]*v1.Pod, error) {
	cache.removeOldPods()

	pods := make([]*v1.Pod, 0)
	addedPods := make(map[string]any)
	cache.pods.Range(func(_, value any) bool {
		pods = append(pods, value.(*v1.Pod))
		addedPods[getObjectKey(value)] = nil
		return true
	})
	cache.oldPods.Range(func(_, value any) bool {
		pod := value.(oldResource[*v1.Pod]).obj
		if _, ok := addedPods[getObjectKey(pod)]; !ok {
			pods = append(pods, pod)
			// Not needed to add to addedPods, since there are no duplicate keys in a map
		}
		return true
	})
	return pods, nil
}

func (cache *K8sInventoryCache) GetSvcs() ([]*v1.Service, error) {
	cache.removeOldSvcs()

	svcs := make([]*v1.Service, 0)
	addedSvcs := make(map[string]any)
	cache.svcs.Range(func(_, value any) bool {
		svcs = append(svcs, value.(*v1.Service))
		addedSvcs[getObjectKey(value)] = nil
		return true
	})
	cache.oldSvcs.Range(func(_, value any) bool {
		svc := value.(oldResource[*v1.Service]).obj
		if _, ok := addedSvcs[getObjectKey(svc)]; !ok {
			svcs = append(svcs, svc)
			// Not needed to add to addedSvcs, since there are no duplicate keys in a map
		}
		return true
	})
	return svcs, nil
}

func getObjectKey(obj any) string {
	switch o := obj.(type) {
	case *v1.Pod:
		return o.Namespace + "/" + o.Name
	case *v1.Service:
		return o.Namespace + "/" + o.Name
	default:
		log.Warnf("getObjectKey: unknown object type: %T", o)
		return ""
	}
}

func (cache *K8sInventoryCache) OnAdd(obj any, isInInitialList bool) {
	switch o := obj.(type) {
	case *v1.Pod:
		key := getObjectKey(o)
		// If the pod is an old pod still cached, remove it from there
		cache.oldPods.Delete(key)
		cache.pods.Store(key, o)
	case *v1.Service:
		key := getObjectKey(o)
		cache.oldSvcs.Delete(key)
		cache.svcs.Store(key, o)
	default:
		log.Warnf("OnAdd: unknown object type: %T", o)
	}
}

func (cache *K8sInventoryCache) OnUpdate(oldObj, newObj any) {
	switch o := newObj.(type) {
	case *v1.Pod:
		cache.pods.Store(getObjectKey(o), o)
	case *v1.Service:
		cache.svcs.Store(getObjectKey(o), o)
	default:
		log.Warnf("OnUpdate: unknown object type: %T", o)
	}
}

func (cache *K8sInventoryCache) OnDelete(obj any) {
	switch o := obj.(type) {
	case *v1.Pod:
		key := getObjectKey(o)
		cache.oldPods.Store(key, oldResource[*v1.Pod]{deletionTimestamp: time.Now(), obj: o})
		cache.pods.Delete(key)
	case *v1.Service:
		key := getObjectKey(o)
		cache.oldSvcs.Store(key, oldResource[*v1.Service]{deletionTimestamp: time.Now(), obj: o})
		cache.svcs.Delete(key)
	default:
		log.Warnf("OnDelete: unknown object type: %T", o)
	}
}
