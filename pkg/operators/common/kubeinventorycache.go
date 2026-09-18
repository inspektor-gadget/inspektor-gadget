// Copyright 2023-2026 The Inspektor Gadget authors
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
	"maps"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	k8sCache "k8s.io/client-go/tools/cache"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/cachedmap"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

var (
	_ metav1.Object  = (*SlimPod)(nil)
	_ runtime.Object = (*SlimPod)(nil)
	_ metav1.Object  = (*SlimService)(nil)
	_ runtime.Object = (*SlimService)(nil)
)

// SlimPod is a reduced version of v1.Pod, it only contains the fields that are
// needed to enrich events. It embeds metav1.TypeMeta and metav1.ObjectMeta so
// it satisfies metav1.Object and runtime.Object, which lets the shared informer
// store it directly via WithTransform (the informer recomputes its store key
// with MetaNamespaceKeyFunc on the transformed object).
type SlimPod struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SlimPodSpec   `json:"spec"`
	Status            SlimPodStatus `json:"status"`
}

type SlimPodSpec struct {
	HostNetwork bool   `json:"hostNetwork"`
	NodeName    string `json:"nodeName"`
}

type SlimPodStatus struct {
	HostIP string `json:"hostIP"`
	PodIP  string `json:"podIP"`
}

func NewSlimPod(p *v1.Pod) *SlimPod {
	return &SlimPod{
		TypeMeta: p.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:            p.Name,
			Namespace:       p.Namespace,
			ResourceVersion: p.ResourceVersion,
			Labels:          p.Labels,
			OwnerReferences: p.OwnerReferences,
		},
		Spec: SlimPodSpec{
			HostNetwork: p.Spec.HostNetwork,
			NodeName:    p.Spec.NodeName,
		},
		Status: SlimPodStatus{
			HostIP: p.Status.HostIP,
			PodIP:  p.Status.PodIP,
		},
	}
}

func (in *SlimPod) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(SlimPod)
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
	return out
}

// SlimService is a reduced version of v1.Service, it only contains the fields
// that are needed to enrich events.
type SlimService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SlimServiceSpec `json:"spec"`
}

type SlimServiceSpec struct {
	ClusterIP string            `json:"clusterIP"`
	Selector  map[string]string `json:"selector,omitempty"`
}

func NewSlimService(s *v1.Service) *SlimService {
	return &SlimService{
		TypeMeta: s.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:            s.Name,
			Namespace:       s.Namespace,
			ResourceVersion: s.ResourceVersion,
			Labels:          s.Labels,
			OwnerReferences: s.OwnerReferences,
		},
		Spec: SlimServiceSpec{
			ClusterIP: s.Spec.ClusterIP,
			Selector:  s.Spec.Selector,
		},
	}
}

func (in *SlimService) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(SlimService)
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Spec.Selector = maps.Clone(in.Spec.Selector)
	return out
}

// K8sInventoryCache is a cache of Kubernetes resources such as pods and services
// that can be used by operators to enrich events.
//
// Objects returned by the Get* methods are the same *SlimPod/*SlimService
// pointers the shared informer produced and are shared across all callers (and
// the informer's own store). They MUST be treated as read-only: mutating a
// returned object (or its Labels/OwnerReferences/Selector maps) corrupts the
// informer cache and races other consumers. Deep-copy first if you need to
// modify or retain a stable view.
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
	clientset kubernetes.Interface

	factory     informers.SharedInformerFactory
	podsHandler k8sCache.ResourceEventHandlerRegistration
	svcsHandler k8sCache.ResourceEventHandlerRegistration

	// Live store. These hold the SAME *SlimPod/*SlimService pointers the
	// informer's transform produced (no extra copy of the data). We own these
	// maps so that, on delete, the live->grace transition is atomic
	// (cachedmap.Remove moves the entry from "current" to the TTL-pruned "old"
	// set under one lock). That closes the lookup gap a delete would otherwise
	// open: client-go drops the object from its own indexer synchronously but
	// dispatches OnDelete to us asynchronously, so reading the informer's indexer
	// directly would briefly miss a just-deleted object before we could re-add
	// it. Here Get always sees it in current or old, never absent.
	pods     cachedmap.CachedMap[string, *SlimPod]
	podsByIp cachedmap.CachedMap[string, *SlimPod]
	svcs     cachedmap.CachedMap[string, *SlimService]
	svcsByIp cachedmap.CachedMap[string, *SlimService]
	// mapsMu guards the map fields above (the pointers, not their contents -
	// cachedmap is internally synchronized). Get* and the event handlers take
	// RLock; Start (assigning the maps) and Close (nil-ing them) take Lock, so a
	// concurrent Stop can never race a lookup into a nil-map panic.
	mapsMu sync.RWMutex

	exit chan struct{}

	// graceTTL is how long deleted entries remain resolvable after deletion.
	// Zero means the default of 2s; settable in tests.
	graceTTL time.Duration

	useCount      int
	useCountMutex sync.Mutex
}

const (
	informerResync = 0 // no resync
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
		return NewSlimPod(t), nil
	case *v1.Service:
		return NewSlimService(t), nil
	default:
		return obj, nil
	}
}

func newCache() (*inventoryCache, error) {
	clientset, err := k8sutil.NewClientsetWithProtobuf("", "kube-inventory-cache")
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
	cache.mapsMu.Lock()
	defer cache.mapsMu.Unlock()
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
		// cachedmap keeps deleted entries resolvable for graceTTL (its "old" set).
		graceTTL := cache.graceTTL
		if graceTTL <= 0 {
			graceTTL = 2 * time.Second
		}
		cache.mapsMu.Lock()
		cache.pods = cachedmap.NewCachedMap[string, *SlimPod](graceTTL)
		cache.podsByIp = cachedmap.NewCachedMap[string, *SlimPod](graceTTL)
		cache.svcs = cachedmap.NewCachedMap[string, *SlimService](graceTTL)
		cache.svcsByIp = cachedmap.NewCachedMap[string, *SlimService](graceTTL)
		cache.mapsMu.Unlock()

		podsInformer := cache.factory.Core().V1().Pods().Informer()
		svcsInformer := cache.factory.Core().V1().Services().Informer()

		// Our handlers maintain the live maps from the transformed *SlimPod/
		// *SlimService objects the informer delivers.
		var err error
		if cache.podsHandler, err = podsInformer.AddEventHandler(cache); err != nil {
			log.Warnf("adding pod event handler: %v", err)
		}
		if cache.svcsHandler, err = svcsInformer.AddEventHandler(cache); err != nil {
			log.Warnf("adding service event handler: %v", err)
		}

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
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	if cache.pods == nil {
		return nil
	}
	return cache.pods.Values()
}

func (cache *inventoryCache) GetPodByName(namespace string, name string) *SlimPod {
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	if cache.pods == nil {
		return nil
	}
	pod, found := cache.pods.Get(namespace + "/" + name)
	if !found {
		return nil
	}
	return pod
}

func (cache *inventoryCache) GetPodByIp(ip string) *SlimPod {
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	if cache.podsByIp == nil {
		return nil
	}
	pod, found := cache.podsByIp.Get(ip)
	if !found {
		return nil
	}
	return pod
}

func (cache *inventoryCache) GetSvcs() []*SlimService {
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	if cache.svcs == nil {
		return nil
	}
	return cache.svcs.Values()
}

func (cache *inventoryCache) GetSvcByName(namespace string, name string) *SlimService {
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	if cache.svcs == nil {
		return nil
	}
	svc, found := cache.svcs.Get(namespace + "/" + name)
	if !found {
		return nil
	}
	return svc
}

func (cache *inventoryCache) GetSvcByIp(ip string) *SlimService {
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	if cache.svcsByIp == nil {
		return nil
	}
	svc, found := cache.svcsByIp.Get(ip)
	if !found {
		return nil
	}
	return svc
}

func (cache *inventoryCache) OnAdd(obj any, _ bool) {
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	switch o := obj.(type) {
	case *SlimPod:
		if cache.pods == nil {
			return
		}
		cache.pods.Add(o.Namespace+"/"+o.Name, o)
		// hostNetwork pods share the node IP, so indexing them by IP would make
		// the IP ambiguous - skip it.
		if ip := o.Status.PodIP; ip != "" && !o.Spec.HostNetwork {
			cache.podsByIp.Add(ip, o)
		}
	case *SlimService:
		if cache.svcs == nil {
			return
		}
		cache.svcs.Add(o.Namespace+"/"+o.Name, o)
		if ip := o.Spec.ClusterIP; ip != "" {
			cache.svcsByIp.Add(ip, o)
		}
	default:
		log.Warnf("OnAdd: unknown object type: %T", o)
	}
}

func (cache *inventoryCache) OnUpdate(oldObj, newObj any) {
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	switch n := newObj.(type) {
	case *SlimPod:
		if cache.pods == nil {
			return
		}
		cache.pods.Add(n.Namespace+"/"+n.Name, n)
		newIP := ""
		if !n.Spec.HostNetwork {
			newIP = n.Status.PodIP
		}
		// Drop the stale IP mapping when a pod's IP changes, otherwise the old
		// IP would keep resolving to this pod.
		if o, ok := oldObj.(*SlimPod); ok && !o.Spec.HostNetwork {
			if oldIP := o.Status.PodIP; oldIP != "" && oldIP != newIP {
				cache.podsByIp.Remove(oldIP)
			}
		}
		if newIP != "" {
			cache.podsByIp.Add(newIP, n)
		}
	case *SlimService:
		if cache.svcs == nil {
			return
		}
		cache.svcs.Add(n.Namespace+"/"+n.Name, n)
		newIP := n.Spec.ClusterIP
		if o, ok := oldObj.(*SlimService); ok {
			if oldIP := o.Spec.ClusterIP; oldIP != "" && oldIP != newIP {
				cache.svcsByIp.Remove(oldIP)
			}
		}
		if newIP != "" {
			cache.svcsByIp.Add(newIP, n)
		}
	default:
		log.Warnf("OnUpdate: unknown object type: %T", n)
	}
}

func (cache *inventoryCache) OnDelete(obj any) {
	// Unwrap the tombstone before locking so we never take RLock recursively
	// (Go's RWMutex RLock is not safely reentrant when a writer is queued).
	if tombstone, ok := obj.(k8sCache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	cache.mapsMu.RLock()
	defer cache.mapsMu.RUnlock()
	switch o := obj.(type) {
	case *SlimPod:
		if cache.pods == nil {
			return
		}
		// cachedmap.Remove atomically moves the entry from "current" to the
		// TTL-pruned "old" set, so a concurrent Get still resolves it during the
		// grace window - there is no gap where it is absent.
		cache.pods.Remove(o.Namespace + "/" + o.Name)
		if ip := o.Status.PodIP; ip != "" && !o.Spec.HostNetwork {
			cache.podsByIp.Remove(ip)
		}
	case *SlimService:
		if cache.svcs == nil {
			return
		}
		cache.svcs.Remove(o.Namespace + "/" + o.Name)
		if ip := o.Spec.ClusterIP; ip != "" {
			cache.svcsByIp.Remove(ip)
		}
	default:
		log.Warnf("OnDelete: unknown object type: %T", o)
	}
}
