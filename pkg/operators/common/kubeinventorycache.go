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

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

// K8sInventoryCache is a cache of Kubernetes resources such as pods and services
// that can be used by operators to enrich events.
type K8sInventoryCache struct {
	clientset *kubernetes.Clientset

	factory informers.SharedInformerFactory
	pods    listersv1.PodLister
	svcs    listersv1.ServiceLister

	exit chan struct{}

	useCount      int
	useCountMutex sync.Mutex
}

const (
	informerResync = 10 * time.Minute
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
		cache.pods = cache.factory.Core().V1().Pods().Lister()
		cache.svcs = cache.factory.Core().V1().Services().Lister()

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

func (cache *K8sInventoryCache) GetPods() ([]*v1.Pod, error) {
	return cache.pods.List(labels.Everything())
}

func (cache *K8sInventoryCache) GetSvcs() ([]*v1.Service, error) {
	return cache.svcs.List(labels.Everything())
}
