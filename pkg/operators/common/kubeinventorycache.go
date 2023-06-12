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
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

// K8sInventoryCache is a cache of Kubernetes resources such as pods and services
// that can be used by operators to enrich events.
type K8sInventoryCache struct {
	clientset *kubernetes.Clientset

	pods atomic.Pointer[v1.PodList]
	svcs atomic.Pointer[v1.ServiceList]

	exit           chan struct{}
	ticker         *time.Ticker
	tickerDuration time.Duration

	useCount      int
	useCountMutex sync.Mutex
}

var (
	cache *K8sInventoryCache
	err   error
	once  sync.Once
)

func GetK8sInventoryCache() (*K8sInventoryCache, error) {
	once.Do(func() {
		cache, err = newCache(1 * time.Second)
	})
	return cache, err
}

func newCache(tickerDuration time.Duration) (*K8sInventoryCache, error) {
	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, fmt.Errorf("creating new k8s clientset: %w", err)
	}

	return &K8sInventoryCache{
		clientset:      clientset,
		tickerDuration: tickerDuration,
	}, nil
}

func (cache *K8sInventoryCache) loop() {
	for {
		select {
		case <-cache.exit:
			return
		case <-cache.ticker.C:
			cache.update()
		}
	}
}

func (cache *K8sInventoryCache) Close() {
	if cache.exit != nil {
		close(cache.exit)
		cache.exit = nil
	}
	if cache.ticker != nil {
		cache.ticker.Stop()
		cache.ticker = nil
	}
}

func (cache *K8sInventoryCache) Start() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// No uses before us, we are the first one
	if cache.useCount == 0 {
		cache.update()
		cache.exit = make(chan struct{})
		cache.ticker = time.NewTicker(cache.tickerDuration)
		go cache.loop()
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

func (cache *K8sInventoryCache) update() {
	pods, err := cache.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("listing pods: %v", err)
		return
	}
	cache.pods.Store(pods)

	svcs, err := cache.clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("listing services: %s", err)
		return
	}
	cache.svcs.Store(svcs)
}

func (cache *K8sInventoryCache) GetPods() *v1.PodList {
	return cache.pods.Load()
}

func (cache *K8sInventoryCache) GetSvcs() *v1.ServiceList {
	return cache.svcs.Load()
}
