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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	k8sCache "k8s.io/client-go/tools/cache"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/cachedmap"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

type SlimObjectMeta struct {
	Name            string                  `json:"name"`
	Namespace       string                  `json:"namespace"`
	ResourceVersion string                  `json:"resourceVersion"`
	Labels          map[string]string       `json:"labels"`
	OwnerReferences []metav1.OwnerReference `json:"ownerReferences"`
}

// SlimPod is a reduced version of v1.Pod, it only contains the fields that are
// needed to enrich events.
type SlimPod struct {
	metav1.TypeMeta `json:",inline"`
	SlimObjectMeta  `json:",inline"`
	Spec            SlimPodSpec   `json:"spec"`
	Status          SlimPodStatus `json:"status"`
}

type SlimPodSpec struct {
	HostNetwork bool `json:"hostNetwork"`
}

type SlimPodStatus struct {
	HostIP string `json:"hostIP"`
	PodIP  string `json:"podIP"`
}

func NewSlimPod(p *v1.Pod) *SlimPod {
	return &SlimPod{
		TypeMeta: p.TypeMeta,
		SlimObjectMeta: SlimObjectMeta{
			Name:            p.Name,
			Namespace:       p.Namespace,
			ResourceVersion: p.ResourceVersion,
			Labels:          p.Labels,
			OwnerReferences: p.OwnerReferences,
		},
		Spec: SlimPodSpec{
			HostNetwork: p.Spec.HostNetwork,
		},
		Status: SlimPodStatus{
			HostIP: p.Status.HostIP,
			PodIP:  p.Status.PodIP,
		},
	}
}

// SlimService is a reduced version of v1.Service, it only contains the fields
// that are needed to enrich events.
type SlimService struct {
	metav1.TypeMeta `json:",inline"`
	SlimObjectMeta  `json:",inline"`
	Spec            SlimServiceSpec `json:"spec"`
}

type SlimServiceSpec struct {
	ClusterIP string `json:"clusterIP"`
}

func NewSlimService(s *v1.Service) *SlimService {
	return &SlimService{
		TypeMeta: s.TypeMeta,
		SlimObjectMeta: SlimObjectMeta{
			Name:            s.Name,
			Namespace:       s.Namespace,
			ResourceVersion: s.ResourceVersion,
			Labels:          s.Labels,
			OwnerReferences: s.OwnerReferences,
		},
		Spec: SlimServiceSpec{
			ClusterIP: s.Spec.ClusterIP,
		},
	}
}

// K8sInventoryCache is a cache of Kubernetes resources such as pods and services
// that can be used by operators to enrich events.
type K8sInventoryCache interface {
	Start()
	Stop()

	GetPods() []*SlimPod
	GetPodByName(namespace string, name string) *SlimPod
	GetPodByIp(ip string) *SlimPod

	GetSvcs() []*SlimService
	GetSvcByName(namespace string, name string) *SlimService
	GetSvcByIp(ip string) *SlimService
}

type inventoryCache struct {
	clientset *kubernetes.Clientset

	factory     informers.SharedInformerFactory
	podsHandler k8sCache.ResourceEventHandlerRegistration
	svcsHandler k8sCache.ResourceEventHandlerRegistration

	pods     cachedmap.CachedMap[string, *SlimPod]
	podsByIp cachedmap.CachedMap[string, *SlimPod]
	svcs     cachedmap.CachedMap[string, *SlimService]
	svcsByIp cachedmap.CachedMap[string, *SlimService]

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

func transformObject(obj any) (any, error) {
	switch t := obj.(type) {
	case *v1.Pod:
		p := &v1.Pod{
			TypeMeta: t.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            t.Name,
				Namespace:       t.Namespace,
				ResourceVersion: t.ResourceVersion,
				Labels:          t.Labels,
				OwnerReferences: t.OwnerReferences,
			},
			Status: v1.PodStatus{
				HostIP: t.Status.HostIP,
				PodIP:  t.Status.PodIP,
			},
		}
		return p, nil
	case *v1.Service:
		s := &v1.Service{
			TypeMeta: t.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            t.Name,
				Namespace:       t.Namespace,
				ResourceVersion: t.ResourceVersion,
				Labels:          t.Labels,
				OwnerReferences: t.OwnerReferences,
			},
			Spec: v1.ServiceSpec{
				ClusterIP: t.Spec.ClusterIP,
			},
		}
		return s, nil
	default:
		return obj, nil
	}
}

func newCache() (*inventoryCache, error) {
	clientset, err := k8sutil.NewClientsetWithProtobuf("")
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
		cache.factory = informers.NewSharedInformerFactoryWithOptions(
			cache.clientset, informerResync, informers.WithTransform(transformObject),
		)
		cache.pods = cachedmap.NewCachedMap[string, *SlimPod](2 * time.Second)
		cache.podsByIp = cachedmap.NewCachedMap[string, *SlimPod](2 * time.Second)
		cache.svcs = cachedmap.NewCachedMap[string, *SlimService](2 * time.Second)
		cache.svcsByIp = cachedmap.NewCachedMap[string, *SlimService](2 * time.Second)

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

func (cache *inventoryCache) GetPods() []*SlimPod {
	return cache.pods.Values()
}

func (cache *inventoryCache) GetPodByName(namespace string, name string) *SlimPod {
	pod, found := cache.pods.Get(namespace + "/" + name)
	if !found {
		return nil
	}
	return pod
}

func (cache *inventoryCache) GetPodByIp(ip string) *SlimPod {
	pod, found := cache.podsByIp.Get(ip)
	if !found {
		return nil
	}
	return pod
}

func (cache *inventoryCache) GetSvcs() []*SlimService {
	return cache.svcs.Values()
}

func (cache *inventoryCache) GetSvcByName(namespace string, name string) *SlimService {
	svc, found := cache.svcs.Get(namespace + "/" + name)
	if !found {
		return nil
	}
	return svc
}

func (cache *inventoryCache) GetSvcByIp(ip string) *SlimService {
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
		slimPod := NewSlimPod(o)
		cache.pods.Add(key, slimPod)
		if ip := slimPod.Status.PodIP; ip != "" {
			cache.podsByIp.Add(ip, slimPod)
		}
	case *v1.Service:
		key, err := k8sCache.MetaNamespaceKeyFunc(o)
		if err != nil {
			log.Warnf("OnAdd: error getting key for service: %v", err)
			return
		}
		slimService := NewSlimService(o)
		cache.svcs.Add(key, slimService)
		if ip := slimService.Spec.ClusterIP; ip != "" {
			cache.svcsByIp.Add(ip, slimService)
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
		slimPod := NewSlimPod(o)
		cache.pods.Add(key, slimPod)
		if ip := slimPod.Status.PodIP; ip != "" {
			cache.podsByIp.Add(ip, slimPod)
		}
	case *v1.Service:
		key, err := k8sCache.MetaNamespaceKeyFunc(o)
		if err != nil {
			log.Warnf("OnUpdate: error getting key for service: %v", err)
			return
		}
		slimService := NewSlimService(o)
		cache.svcs.Add(key, slimService)
		if ip := slimService.Spec.ClusterIP; ip != "" {
			cache.svcsByIp.Add(ip, slimService)
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
