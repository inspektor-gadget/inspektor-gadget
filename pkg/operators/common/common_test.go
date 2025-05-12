// Copyright 2025 The Inspektor Gadget authors
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
	"bytes"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/cachedmap"
)

func TestStartIncrementsUseCount(t *testing.T) {
	fakeClientSet := fake.NewSimpleClientset()
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
}

func TestInventoryCacheAdd(t *testing.T) {
	type addTestCase struct {
		testName      string
		kind          string
		initialObj    any
		expectedName  string
		expectedIP    string
		ok            bool
		expectedError string
	}

	testCases := []addTestCase{
		{
			testName:     "Add valid Pod with IP",
			kind:         "pod",
			initialObj:   constructPod("test-pod", "default", "1.2.3.4"),
			expectedName: "test-pod",
			expectedIP:   "1.2.3.4",
			ok:           true,
		},
		{
			testName:     "Add valid Service with ClusterIP",
			kind:         "svc",
			initialObj:   constructService("test-svc", "default", "10.0.0.1"),
			expectedName: "test-svc",
			expectedIP:   "10.0.0.1",
			ok:           true,
		},
		{
			testName:     "Add Pod with no IP",
			kind:         "pod",
			initialObj:   constructPod("no-ip-pod", "default", ""),
			expectedName: "no-ip-pod",
			expectedIP:   "",
			ok:           true,
		},
		{
			testName:     "Add Service with no ClusterIP",
			kind:         "svc",
			initialObj:   constructService("no-ip-svc", "default", ""),
			expectedName: "no-ip-svc",
			expectedIP:   "",
			ok:           true,
		},
		{
			testName: "Add Pod with invalid key",
			kind:     "pod",
			// Create a pod with no metadata to trigger a key error.
			initialObj:    &v1.Pod{},
			expectedError: "OnAdd: empty key for pod",
			ok:            false,
		},
		{
			testName:      "Add unknown object",
			kind:          "unknown",
			initialObj:    "not a valid object",
			expectedError: "OnAdd: unknown object type:",
			ok:            false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			// Prepare the cache with all maps.
			cache := &inventoryCache{
				pods:     cachedmap.NewCachedMap[string, *SlimPod](time.Second),
				podsByIp: cachedmap.NewCachedMap[string, *SlimPod](time.Second),
				svcs:     cachedmap.NewCachedMap[string, *SlimService](time.Second),
				svcsByIp: cachedmap.NewCachedMap[string, *SlimService](time.Second),
			}

			// If we expect an error, capture log output.
			if !tc.ok {
				var logBuffer bytes.Buffer
				origOut := logrus.StandardLogger().Out
				logrus.SetOutput(&logBuffer)
				defer logrus.SetOutput(origOut)

				cache.OnAdd(tc.initialObj, false)
				logContent := logBuffer.String()
				assert.Contains(t, logContent, tc.expectedError)
				return
			}

			// Otherwise, perform the addition.
			cache.OnAdd(tc.initialObj, false)

			// Verify results based on kind.
			switch tc.kind {
			case "pod":
				retrieved := cache.GetPodByName("default", tc.expectedName)
				require.NotNil(t, retrieved, "expected pod to be added")
				assert.Equal(t, tc.expectedName, retrieved.Name)
				if tc.expectedIP != "" {
					retrievedByIP := cache.GetPodByIp(tc.expectedIP)
					require.NotNil(t, retrievedByIP, "expected pod to be retrievable by IP")
					assert.Equal(t, tc.expectedName, retrievedByIP.Name)
				}
			case "svc":
				retrieved := cache.GetSvcByName("default", tc.expectedName)
				require.NotNil(t, retrieved, "expected service to be added")
				assert.Equal(t, tc.expectedName, retrieved.Name)
				if tc.expectedIP != "" {
					retrievedByIP := cache.GetSvcByIp(tc.expectedIP)
					require.NotNil(t, retrievedByIP, "expected service to be retrievable by IP")
					assert.Equal(t, tc.expectedName, retrievedByIP.Name)
				}
			}
		})
	}
}

func TestInventoryCacheUpdate(t *testing.T) {
	type updateTestCase struct {
		testName      string
		kind          string
		initialObj    any
		updatedObj    any
		expectedIP    string
		ok            bool
		expectedError string
	}

	testCases := []updateTestCase{
		{
			testName:   "Update Pod IP",
			kind:       "pod",
			initialObj: constructPod("test-pod", "default", "1.2.3.4"),
			updatedObj: constructPod("test-pod", "default", "5.6.7.8"),
			expectedIP: "5.6.7.8",
			ok:         true,
		},
		{
			testName:   "Update Service ClusterIP",
			kind:       "svc",
			initialObj: constructService("test-svc", "default", "10.0.0.1"),
			updatedObj: constructService("test-svc", "default", "10.0.0.2"),
			expectedIP: "10.0.0.2",
			ok:         true,
		},
		{
			testName:   "Update Pod with invalid key",
			kind:       "pod",
			initialObj: constructPod("invalid-pod", "default", "1.2.3.4"),
			// Updated object is missing metadata to force key error.
			updatedObj:    &v1.Pod{},
			expectedError: "OnUpdate: empty key for pod",
			ok:            false,
		},
		{
			testName:      "Update unknown object",
			kind:          "unknown",
			initialObj:    constructPod("some-pod", "default", "1.2.3.4"),
			updatedObj:    "not a valid object",
			expectedError: "OnUpdate: unknown object type:",
			ok:            false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			cache := &inventoryCache{
				pods:     cachedmap.NewCachedMap[string, *SlimPod](time.Nanosecond),
				podsByIp: cachedmap.NewCachedMap[string, *SlimPod](time.Nanosecond),
				svcs:     cachedmap.NewCachedMap[string, *SlimService](time.Nanosecond),
				svcsByIp: cachedmap.NewCachedMap[string, *SlimService](time.Nanosecond),
			}

			cache.OnAdd(tc.initialObj, false)

			if !tc.ok {
				var logBuffer bytes.Buffer
				origOut := logrus.StandardLogger().Out
				logrus.SetOutput(&logBuffer)
				defer logrus.SetOutput(origOut)

				cache.OnUpdate(tc.initialObj, tc.updatedObj)
				logContent := logBuffer.String()
				assert.Contains(t, logContent, tc.expectedError)
				return
			}

			cache.OnUpdate(tc.initialObj, tc.updatedObj)

			switch tc.kind {
			case "pod":
				retrieved := cache.GetPodByName("default", "test-pod")
				require.NotNil(t, retrieved, "expected pod to exist after update")
				assert.Equal(t, tc.expectedIP, retrieved.Status.PodIP)
				retrievedByIP := cache.GetPodByIp(tc.expectedIP)
				require.NotNil(t, retrievedByIP, "expected pod to be retrievable by new IP")
			case "svc":
				retrieved := cache.GetSvcByName("default", "test-svc")
				require.NotNil(t, retrieved, "expected service to exist after update")
				assert.Equal(t, tc.expectedIP, retrieved.Spec.ClusterIP)
				retrievedByIP := cache.GetSvcByIp(tc.expectedIP)
				require.NotNil(t, retrievedByIP, "expected service to be retrievable by new IP")
			}
		})
	}
}

func TestInventoryCacheDelete(t *testing.T) {
	type deleteTestCase struct {
		testName      string
		kind          string
		initialObj    any
		ok            bool
		expectedError string
	}

	testCases := []deleteTestCase{
		{
			testName:   "Delete Pod",
			kind:       "pod",
			initialObj: constructPod("test-pod", "default", "1.2.3.4"),
			ok:         true,
		},
		{
			testName:   "Delete Service",
			kind:       "svc",
			initialObj: constructService("test-svc", "default", "10.0.0.1"),
			ok:         true,
		},
		{
			testName:      "Delete unknown object",
			kind:          "unknown",
			initialObj:    "not a valid object",
			expectedError: "OnDelete: unknown object type:",
			ok:            false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			// Use a very short duration so that cache entries can expire.
			cache := &inventoryCache{
				pods:     cachedmap.NewCachedMap[string, *SlimPod](time.Nanosecond),
				podsByIp: cachedmap.NewCachedMap[string, *SlimPod](time.Nanosecond),
				svcs:     cachedmap.NewCachedMap[string, *SlimService](time.Nanosecond),
				svcsByIp: cachedmap.NewCachedMap[string, *SlimService](time.Nanosecond),
			}

			if tc.ok {
				cache.OnAdd(tc.initialObj, false)
			}

			if !tc.ok {
				var logBuffer bytes.Buffer
				origOut := logrus.StandardLogger().Out
				logrus.SetOutput(&logBuffer)
				defer logrus.SetOutput(origOut)

				cache.OnDelete(tc.initialObj)
				logContent := logBuffer.String()
				assert.Contains(t, logContent, tc.expectedError)
				return
			}
			cache.OnDelete(tc.initialObj)

			start := time.Now()
			for {
				if tc.kind == "pod" {
					rtvdName := cache.GetPodByName(tc.initialObj.(*v1.Pod).Namespace, tc.initialObj.(*v1.Pod).Name)
					rtvdIp := cache.GetPodByIp(tc.initialObj.(*v1.Pod).Status.PodIP)
					if rtvdName == nil && rtvdIp == nil {
						break
					}
				} else if tc.kind == "svc" {
					rtvdName := cache.GetSvcByName(tc.initialObj.(*v1.Service).Namespace, tc.initialObj.(*v1.Service).Name)
					rtvdIp := cache.GetSvcByIp(tc.initialObj.(*v1.Service).Spec.ClusterIP)
					if rtvdName == nil && rtvdIp == nil {
						break
					}
				}
				time.Sleep(time.Nanosecond)

				if time.Since(start) > 1*time.Second {
					t.Fatalf("Timed out waiting for object to be deleted")
				}
			}
		})
	}
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
