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

// TODOS: 1. update removes previous? 2. add "" key pod/svc

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

// ---------- Add Category ----------

func TestInventoryCacheAdd(t *testing.T) {
	type addTestCase struct {
		testName      string
		kind          string // "pod" or "svc"
		initialObj    any
		expectedName  string // used for lookup in ObjectMeta.Name
		expectedIP    string // PodIP for pods, ClusterIP for services; if empty, no lookup by IP is expected
		ok            bool   // if false, we expect an error log
		expectedError string // expected substring in log
	}

	testCases := []addTestCase{
		{
			testName: "Add valid Pod with IP",
			kind:     "pod",
			initialObj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Status: v1.PodStatus{
					PodIP: "1.2.3.4",
				},
			},
			expectedName: "test-pod",
			expectedIP:   "1.2.3.4",
			ok:           true,
		},
		{
			testName: "Add valid Service with ClusterIP",
			kind:     "svc",
			initialObj: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-svc",
					Namespace: "default",
				},
				Spec: v1.ServiceSpec{
					ClusterIP: "10.0.0.1",
				},
			},
			expectedName: "test-svc",
			expectedIP:   "10.0.0.1",
			ok:           true,
		},
		{
			testName: "Add Pod with no IP",
			kind:     "pod",
			initialObj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-ip-pod",
					Namespace: "default",
				},
				Status: v1.PodStatus{
					PodIP: "",
				},
			},
			expectedName: "no-ip-pod",
			expectedIP:   "",
			ok:           true,
		},
		{
			testName: "Add Service with no ClusterIP",
			kind:     "svc",
			initialObj: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-ip-svc",
					Namespace: "default",
				},
				Spec: v1.ServiceSpec{
					ClusterIP: "",
				},
			},
			expectedName: "no-ip-svc",
			expectedIP:   "",
			ok:           true,
		},
		{
			testName: "Add Pod with invalid key",
			kind:     "pod",
			// Create a pod with no metadata to trigger a key error.
			initialObj:    &v1.Pod{},
			expectedError: "OnAdd: error getting key for pod:",
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
			if tc.kind == "pod" {
				retrieved := cache.GetPodByName("default", tc.expectedName)
				require.NotNil(t, retrieved, "expected pod to be added")
				assert.Equal(t, tc.expectedName, retrieved.Name)
				if tc.expectedIP != "" {
					retrievedByIP := cache.GetPodByIp(tc.expectedIP)
					require.NotNil(t, retrievedByIP, "expected pod to be retrievable by IP")
					assert.Equal(t, tc.expectedName, retrievedByIP.Name)
				}
			} else if tc.kind == "svc" {
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
		kind          string // "pod" or "svc"
		initialObj    any
		updatedObj    any
		expectedIP    string // expected new IP after update (PodIP or ClusterIP)
		ok            bool   // if false, we expect an error log
		expectedError string // expected substring in log
	}

	testCases := []updateTestCase{
		{
			testName: "Update Pod IP",
			kind:     "pod",
			initialObj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Status: v1.PodStatus{
					PodIP: "1.2.3.4",
				},
			},
			updatedObj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Status: v1.PodStatus{
					PodIP: "5.6.7.8",
				},
			},
			expectedIP: "5.6.7.8",
			ok:         true,
		},
		{
			testName: "Update Service ClusterIP",
			kind:     "svc",
			initialObj: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-svc",
					Namespace: "default",
				},
				Spec: v1.ServiceSpec{
					ClusterIP: "10.0.0.1",
				},
			},
			updatedObj: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-svc",
					Namespace: "default",
				},
				Spec: v1.ServiceSpec{
					ClusterIP: "10.0.0.2",
				},
			},
			expectedIP: "10.0.0.2",
			ok:         true,
		},
		{
			testName: "Update Pod with invalid key",
			kind:     "pod",
			initialObj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-pod",
					Namespace: "default",
				},
				Status: v1.PodStatus{
					PodIP: "1.2.3.4",
				},
			},
			// Updated object is missing metadata to force key error.
			updatedObj:    &v1.Pod{},
			expectedError: "OnUpdate: error getting key for pod:",
			ok:            false,
		},
		{
			testName: "Update unknown object",
			kind:     "unknown",
			initialObj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-pod",
					Namespace: "default",
				},
				Status: v1.PodStatus{
					PodIP: "1.2.3.4",
				},
			},
			updatedObj:    "not a valid object",
			expectedError: "OnUpdate: unknown object type:",
			ok:            false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			cache := &inventoryCache{
				pods:     cachedmap.NewCachedMap[string, *SlimPod](time.Second),
				podsByIp: cachedmap.NewCachedMap[string, *SlimPod](time.Second),
				svcs:     cachedmap.NewCachedMap[string, *SlimService](time.Second),
				svcsByIp: cachedmap.NewCachedMap[string, *SlimService](time.Second),
			}

			// Add the initial object.
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

			// Otherwise, perform the update.
			cache.OnUpdate(tc.initialObj, tc.updatedObj)

			if tc.kind == "pod" {
				retrieved := cache.GetPodByName("default", "test-pod")
				require.NotNil(t, retrieved, "expected pod to exist after update")
				assert.Equal(t, tc.expectedIP, retrieved.Status.PodIP)
				retrievedByIP := cache.GetPodByIp(tc.expectedIP)
				require.NotNil(t, retrievedByIP, "expected pod to be retrievable by new IP")
			} else if tc.kind == "svc" {
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
		kind          string // "pod" or "svc"
		initialObj    any
		expectedName  string // name used for lookup before deletion
		ip            string // IP (or ClusterIP) used for lookup before deletion
		ok            bool   // if false, we expect an error log
		expectedError string // expected substring in log
	}

	testCases := []deleteTestCase{
		{
			testName: "Delete Pod",
			kind:     "pod",
			initialObj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Status: v1.PodStatus{
					PodIP: "1.2.3.4",
				},
			},
			expectedName: "test-pod",
			ip:           "1.2.3.4",
			ok:           true,
		},
		{
			testName: "Delete Service",
			kind:     "svc",
			initialObj: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-svc",
					Namespace: "default",
				},
				Spec: v1.ServiceSpec{
					ClusterIP: "10.0.0.1",
				},
			},
			expectedName: "test-svc",
			ip:           "10.0.0.1",
			ok:           true,
		},
		{
			testName: "Delete Pod with invalid key",
			kind:     "pod",
			// Initial valid pod.
			initialObj: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Status: v1.PodStatus{
					PodIP: "1.2.3.4",
				},
			},
			expectedError: "OnDelete: error getting key for pod:",
			ok:            false,
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

			// Add the object if it is a valid one.
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

			// Otherwise, delete the object and verify removal.
			cache.OnDelete(tc.initialObj)
			// Wait briefly to allow deletion propagation.
			time.Sleep(time.Millisecond)

			if tc.kind == "pod" {
				retrieved := cache.GetPodByName("default", tc.expectedName)
				require.Nil(t, retrieved, "expected pod to be deleted")
				retrievedByIP := cache.GetPodByIp(tc.ip)
				require.Nil(t, retrievedByIP, "expected pod to be deleted by IP")
			} else if tc.kind == "svc" {
				retrieved := cache.GetSvcByName("default", tc.expectedName)
				require.Nil(t, retrieved, "expected service to be deleted")
				retrievedByIP := cache.GetSvcByIp(tc.ip)
				require.Nil(t, retrievedByIP, "expected service to be deleted by IP")
			}
		})
	}
}
