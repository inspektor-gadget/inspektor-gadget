// Copyright 2025-2026 The Inspektor Gadget authors
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/cachedmap"
)

const eventuallyTimeout = 2 * time.Second

func TestStartIncrementsUseCount(t *testing.T) {
	fakeClientSet := fake.NewClientset()
	cache := &inventoryCache{
		clientset: fakeClientSet,
	}

	require.Equal(t, 0, cache.useCount)

	cache.Start()
	require.Equal(t, 1, cache.useCount)

	cache.Start()
	require.Equal(t, 2, cache.useCount)

	cache.Stop()
	require.Equal(t, 1, cache.useCount)

	cache.Stop()
	require.Equal(t, 0, cache.useCount)

	// Verify resources are cleaned up after last Stop
	assert.Nil(t, cache.factory)
	assert.Nil(t, cache.pods)
	assert.Nil(t, cache.svcs)
}

// TestInventoryCacheInformer drives a real shared informer (over a fake
// clientset) end-to-end. It proves the informer accepts our custom transformed
// type (*SlimPod/*SlimService) and that by-name and by-IP indexer lookups, plus
// updates and deletions, behave as expected.
func TestInventoryCacheInformer(t *testing.T) {
	pod := constructPod("test-pod", "default", "1.2.3.4")
	svc := constructService("test-svc", "default", "10.0.0.1")
	cache := &inventoryCache{
		clientset: fake.NewClientset(pod, svc),
		graceTTL:  200 * time.Millisecond,
	}
	cache.Start()
	defer cache.Stop()

	// Initial objects are stored via the transform and reachable by name and IP.
	require.Eventually(t, func() bool {
		return cache.GetPodByName("default", "test-pod") != nil
	}, eventuallyTimeout, 5*time.Millisecond)

	gotPod := cache.GetPodByName("default", "test-pod")
	require.NotNil(t, gotPod)
	assert.Equal(t, "test-pod", gotPod.Name)
	assert.Equal(t, "1.2.3.4", gotPod.Status.PodIP)

	require.NotNil(t, cache.GetPodByIp("1.2.3.4"))
	require.NotNil(t, cache.GetSvcByName("default", "test-svc"))
	require.NotNil(t, cache.GetSvcByIp("10.0.0.1"))

	// GetPods/GetSvcs return the live set.
	assert.Len(t, cache.GetPods(), 1)
	assert.Len(t, cache.GetSvcs(), 1)

	// Update the pod IP; the new IP must resolve and the stale IP must be dropped.
	updated := constructPod("test-pod", "default", "5.6.7.8")
	_, err := cache.clientset.CoreV1().Pods("default").Update(context.TODO(), updated, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return cache.GetPodByIp("5.6.7.8") != nil && cache.GetPodByIp("1.2.3.4") == nil
	}, eventuallyTimeout, 5*time.Millisecond)

	// Delete the pod; after the grace TTL it must no longer resolve.
	err = cache.clientset.CoreV1().Pods("default").Delete(context.TODO(), "test-pod", metav1.DeleteOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return cache.GetPodByName("default", "test-pod") == nil &&
			cache.GetPodByIp("5.6.7.8") == nil
	}, 3*time.Second, 5*time.Millisecond)
}

// TestOnDeleteAtomicGrace verifies the gap-closure guarantee: deleting an object
// moves it from the live map to the grace window atomically, so a lookup
// immediately after OnDelete still resolves it (never a gap where it is absent),
// and it disappears only after the grace TTL.
func TestOnDeleteAtomicGrace(t *testing.T) {
	ttl := 100 * time.Millisecond
	cache := &inventoryCache{
		pods:     cachedmap.NewCachedMap[string, *SlimPod](ttl),
		podsByIp: cachedmap.NewCachedMap[string, *SlimPod](ttl),
		svcs:     cachedmap.NewCachedMap[string, *SlimService](ttl),
		svcsByIp: cachedmap.NewCachedMap[string, *SlimService](ttl),
	}
	defer func() {
		cache.pods.Close()
		cache.podsByIp.Close()
		cache.svcs.Close()
		cache.svcsByIp.Close()
	}()

	pod := NewSlimPod(constructPod("test-pod", "default", "1.2.3.4"))
	svc := NewSlimService(constructService("test-svc", "default", "10.0.0.1"))

	cache.OnAdd(pod, false)
	cache.OnAdd(svc, false)
	require.NotNil(t, cache.GetPodByName("default", "test-pod"))
	require.NotNil(t, cache.GetPodByIp("1.2.3.4"))
	require.NotNil(t, cache.GetSvcByName("default", "test-svc"))
	require.NotNil(t, cache.GetSvcByIp("10.0.0.1"))

	cache.OnDelete(pod)
	cache.OnDelete(svc)

	// Atomic handoff: immediately resolvable after delete (no gap).
	require.NotNil(t, cache.GetPodByName("default", "test-pod"), "must stay resolvable in grace right after delete")
	require.NotNil(t, cache.GetPodByIp("1.2.3.4"))
	require.NotNil(t, cache.GetSvcByName("default", "test-svc"))
	require.NotNil(t, cache.GetSvcByIp("10.0.0.1"))

	// Gone after the grace TTL expires.
	require.Eventually(t, func() bool {
		return cache.GetPodByName("default", "test-pod") == nil &&
			cache.GetPodByIp("1.2.3.4") == nil &&
			cache.GetSvcByName("default", "test-svc") == nil &&
			cache.GetSvcByIp("10.0.0.1") == nil
	}, eventuallyTimeout, 5*time.Millisecond)
}

func TestSlimDeepCopyObject(t *testing.T) {
	pod := NewSlimPod(constructPod("p", "default", "1.2.3.4"))
	pod.Labels = map[string]string{"a": "b"}
	cp := pod.DeepCopyObject().(*SlimPod)
	require.NotSame(t, pod, cp)
	cp.Labels["a"] = "c"
	assert.Equal(t, "b", pod.Labels["a"], "deep copy must not share the labels map")

	svc := NewSlimService(constructService("s", "default", "10.0.0.1"))
	svc.Spec.Selector = map[string]string{"app": "x"}
	scp := svc.DeepCopyObject().(*SlimService)
	require.NotSame(t, svc, scp)
	assert.Equal(t, "10.0.0.1", scp.Spec.ClusterIP)
	scp.Spec.Selector["app"] = "y"
	assert.Equal(t, "x", svc.Spec.Selector["app"], "deep copy must not share the selector map")
}

func TestHostNetworkPodNotIndexedByIP(t *testing.T) {
	ttl := time.Second
	cache := &inventoryCache{
		pods:     cachedmap.NewCachedMap[string, *SlimPod](ttl),
		podsByIp: cachedmap.NewCachedMap[string, *SlimPod](ttl),
		svcs:     cachedmap.NewCachedMap[string, *SlimService](ttl),
		svcsByIp: cachedmap.NewCachedMap[string, *SlimService](ttl),
	}
	defer func() {
		cache.pods.Close()
		cache.podsByIp.Close()
		cache.svcs.Close()
		cache.svcsByIp.Close()
	}()

	hostNetPod := NewSlimPod(constructPod("host-pod", "default", "10.0.0.5"))
	hostNetPod.Spec.HostNetwork = true
	cache.OnAdd(hostNetPod, false)

	// Resolvable by name, but NOT by its (node-shared) IP.
	require.NotNil(t, cache.GetPodByName("default", "host-pod"))
	assert.Nil(t, cache.GetPodByIp("10.0.0.5"), "hostNetwork pod must not be indexed by IP")
}

// TestConcurrentGetAndStop exercises the RWMutex: concurrent Get* calls while
// Stop() tears the cache down must not panic or data-race (run with -race).
func TestConcurrentGetAndStop(t *testing.T) {
	cache := &inventoryCache{
		clientset: fake.NewClientset(constructPod("p", "default", "1.2.3.4")),
		graceTTL:  200 * time.Millisecond,
	}
	cache.Start()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10000; i++ {
			cache.GetPodByName("default", "p")
			cache.GetPodByIp("1.2.3.4")
			cache.GetPods()
		}
	}()

	cache.Stop() // last user -> Close() nils the maps while Get* may be running
	<-done
}

func constructPod(name, namespace, ip string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: v1.PodStatus{
			PodIP: ip,
		},
	}
}

func constructService(name, namespace, clusterIP string) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.ServiceSpec{
			ClusterIP: clusterIP,
		},
	}
}
