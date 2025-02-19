// Copyright 2024 The Inspektor Gadget authors
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

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestString2Runtime(t *testing.T) {
	tests := []struct {
		description string
		name        string
		expected    RuntimeName
	}{
		{
			description: "result should be docker ",
			name:        "docker",
			expected: RuntimeName(
				"docker",
			),
		},
		{
			description: "result should be containerd ",
			name:        "containerd",
			expected: RuntimeName(
				"containerd",
			),
		},
		{
			description: "result should be cri-o ",
			name:        "cri-o",
			expected: RuntimeName(
				"cri-o",
			),
		},
		{
			description: "result should be podman",
			name:        "podman",
			expected: RuntimeName(
				"podman",
			),
		},
		{
			description: "result should be unknown",
			name:        "unknown",
			expected: RuntimeName(
				"unknown",
			),
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			actual := String2RuntimeName(test.name)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestContainerOperations(t *testing.T) {
	c := &CommonData{
		K8s: K8sMetadata{
			Node: "testNode",
			BasicK8sMetadata: BasicK8sMetadata{
				PodName:       "testPod",
				Namespace:     "testNamespace",
				ContainerName: "testContainer",
				PodLabels: map[string]string{
					"app":   "nginx",
					"valid": "yes",
				},
			},
		},
		Runtime: BasicRuntimeMetadata{
			ContainerImageName:   "testContainerImage",
			RuntimeName:          "testRuntime",
			ContainerImageDigest: "testDigest",
			ContainerName:        "testContainer",
			ContainerID:          "testContainerID",
		},
	}
	basicK8sMetadata := BasicK8sMetadata{}
	basicRuntimeMetadata := BasicRuntimeMetadata{}
	basicK8sMetadata = c.K8s.BasicK8sMetadata
	basicRuntimeMetadata = c.Runtime
	node := c.GetNode()
	podName := c.GetPod()
	namespace := c.GetNamespace()
	containerName := c.GetContainer()
	containerImageName := c.GetContainerImageName()
	isEnriched := basicK8sMetadata.IsEnriched()
	isEnrichedRuntime := basicRuntimeMetadata.IsEnriched()
	assert.Equal(t, "testNode", node)
	assert.Equal(t, "testPod", podName)
	assert.Equal(t, "testNamespace", namespace)
	assert.Equal(t, "testContainer", containerName)
	assert.Equal(t, "testContainerImage", containerImageName)
	assert.Equal(t, true, isEnriched)
	assert.Equal(t, true, isEnrichedRuntime)
}

type MockContainer struct{}

func (m *MockContainer) K8sMetadata() *BasicK8sMetadata {
	return &BasicK8sMetadata{
		PodLabels: map[string]string{
			"app":   "nginx",
			"valid": "yes",
		},
		PodName:       "testPod",
		Namespace:     "testNamespace",
		ContainerName: "containerName",
	}
}

func (m *MockContainer) RuntimeMetadata() *BasicRuntimeMetadata {
	return &BasicRuntimeMetadata{
		ContainerID:   "containerID",
		ContainerName: "containerName",
		RuntimeName:   "runtimeName",
		ContainerPID:  1,
	}
}

func (m *MockContainer) UsesHostNetwork() bool { return false }

func (m *MockContainer) ContainerPid() uint32 { return 0 }

func (m *MockContainer) K8sOwnerReference() *K8sOwnerReference {
	return &K8sOwnerReference{
		Kind: "testKind",
		Name: "testName",
	}
}

func TestK8sMetadataUnmarshal(t *testing.T) {
	input := `{"podLabels": "app=nginx,valid=yes"}`
	expected := &K8sMetadata{
		BasicK8sMetadata: BasicK8sMetadata{
			PodLabels: map[string]string{
				"app":   "nginx",
				"valid": "yes",
			},
		},
	}

	var actual K8sMetadata
	err := json.Unmarshal([]byte(input), &actual)

	assert.NoError(t, err)
	assert.Equal(t, expected.PodLabels, actual.PodLabels)
}

func TestK8sMetadataUnmarshalBadFormat(t *testing.T) {
	input := `{"podLabels": "app=nginx,foo:bar,valid=yes,invalid"}`
	err := json.Unmarshal([]byte(input), &K8sMetadata{})
	assert.Error(t, err)
}

func TestK8sMetadataUnmarshalBadFormat2(t *testing.T) {
	input := `{"podlabels":{"k8s-app":"kube-dns","kubernetes.io/cluster-service":"true","kubernetes.io/name":"CoreDNS"}}`
	expected := &K8sMetadata{
		BasicK8sMetadata: BasicK8sMetadata{
			PodLabels: map[string]string{
				"k8s-app":                       "kube-dns",
				"kubernetes.io/cluster-service": "true",
				"kubernetes.io/name":            "CoreDNS",
			},
		},
	}

	var actual K8sMetadata
	err := json.Unmarshal([]byte(input), &actual)

	assert.NoError(t, err)
	assert.Equal(t, expected.PodLabels, actual.PodLabels)
}

func TestSetPodMetadata(t *testing.T) {
	tests := []struct {
		description string
		output      *CommonData
	}{
		{
			description: "result should",
			output: &CommonData{
				K8s: K8sMetadata{
					BasicK8sMetadata: BasicK8sMetadata{
						PodName:   "testPod",
						Namespace: "testNamespace",
						PodLabels: map[string]string{
							"app":   "nginx",
							"valid": "yes",
						},
					},
					Owner: K8sOwnerReference{
						Kind: "testKind",
						Name: "testName",
					},
				},
				Runtime: BasicRuntimeMetadata{
					RuntimeName: "runtimeName",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			c := &CommonData{}
			m := &MockContainer{}
			c.SetPodMetadata(m)
			assert.Equal(t, test.output.K8s.PodName, c.K8s.PodName)
			assert.Equal(t, test.output.K8s.Namespace, c.K8s.Namespace)
			assert.Equal(t, test.output.K8s.PodLabels, c.K8s.PodLabels)
			assert.Equal(t, test.output.K8s.Owner, c.K8s.Owner)
			assert.Equal(t, test.output.Runtime.RuntimeName, c.Runtime.RuntimeName)
		})
	}
}

func TestSetContainerMetadata(t *testing.T) {
	tests := []struct {
		description string
		expected    *CommonData
	}{
		{
			description: "result should",
			expected: &CommonData{
				K8s: K8sMetadata{
					BasicK8sMetadata: BasicK8sMetadata{
						ContainerName: "containerName",
						PodName:       "testPod",
						Namespace:     "testNamespace",
						PodLabels: map[string]string{
							"app":   "nginx",
							"valid": "yes",
						},
					},
					Owner: K8sOwnerReference{
						Kind: "testKind",
						Name: "testName",
					},
				},
				Runtime: BasicRuntimeMetadata{
					ContainerID:   "containerID",
					ContainerName: "containerName",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			c := &CommonData{}
			m := &MockContainer{}
			c.SetContainerMetadata(m)
			assert.Equal(t, test.expected.K8s.ContainerName, c.K8s.ContainerName)
			assert.Equal(t, test.expected.K8s.PodName, c.K8s.PodName)
			assert.Equal(t, test.expected.K8s.Namespace, c.K8s.Namespace)
			assert.Equal(t, test.expected.K8s.PodLabels, c.K8s.PodLabels)
			assert.Equal(t, test.expected.K8s.Owner, c.K8s.Owner)
			assert.Equal(t, test.expected.Runtime.ContainerID, c.Runtime.ContainerID)
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		description string
		e           *L3Endpoint
		expected    string
	}{
		{
			description: "result should be pod",
			e: &L3Endpoint{
				Kind:      "pod",
				Namespace: "test",
				Name:      "testName",
			},
			expected: "p/test/testName",
		},
		{
			description: "result should be svc",
			e: &L3Endpoint{
				Kind:      "svc",
				Namespace: "test",
				Name:      "testName",
			},
			expected: "s/test/testName",
		},
		{
			description: "result should be Raw",
			e: &L3Endpoint{
				Kind:      "raw",
				Namespace: "test",
				Name:      "testName",
				Addr:      "testAddr",
			},
			expected: "r/testAddr",
		},
		{
			description: "result should be unknown",
			e: &L3Endpoint{
				Version: 6,
				Addr:    "testAddr",
			},
			expected: "[testAddr]",
		},
		{
			description: "result should be unknown",
			e: &L3Endpoint{
				Version: 4,
				Addr:    "testAddr",
			},
			expected: "testAddr",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			actual := test.e.String()
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestErr(t *testing.T) {
	tests := []struct {
		name  string
		msg   string
		event Event
	}{
		{
			name: "returns an event",

			msg: "test",
			event: Event{
				CommonData: CommonData{
					K8s: K8sMetadata{
						Node: "",
					},
				},
				Type:    "err",
				Message: "test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := Err(test.msg)
			assert.Equal(t, test.event, actual)
		})
	}
}

func TestWarn(t *testing.T) {
	tests := []struct {
		name  string
		msg   string
		event Event
	}{
		{
			name: "returns an event",

			msg: "test",
			event: Event{
				CommonData: CommonData{
					K8s: K8sMetadata{
						Node: "",
					},
				},
				Type:    "warn",
				Message: "test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := Warn(test.msg)
			assert.Equal(t, test.event, actual)
		})
	}
}

func TestDebug(t *testing.T) {
	tests := []struct {
		name  string
		msg   string
		event Event
	}{
		{
			name: "returns an event",

			msg: "test",
			event: Event{
				CommonData: CommonData{
					K8s: K8sMetadata{
						Node: "",
					},
				},
				Type:    "debug",
				Message: "test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := Debug(test.msg)
			assert.Equal(t, test.event, actual)
		})
	}
}

func TestInfo(t *testing.T) {
	tests := []struct {
		name  string
		msg   string
		event Event
	}{
		{
			name: "returns an event",

			msg: "test",
			event: Event{
				CommonData: CommonData{
					K8s: K8sMetadata{
						Node: "",
					},
				},
				Type:    "info",
				Message: "test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := Info(test.msg)
			assert.Equal(t, test.event, actual)
		})
	}
}

func TestEventString(t *testing.T) {
	tests := []struct {
		name     string
		i        interface{}
		expected string
		hasError bool
	}{
		{
			name:     "returns a string",
			i:        "testing",
			expected: "\"testing\"",
		},
		{
			name:     "returns a string",
			i:        1,
			expected: "1",
		},
		{
			name:     "returns a string",
			i:        nil,
			expected: "null",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := EventString(test.i)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestParsePodLabels(t *testing.T) {
	tests := []struct {
		name          string
		s             string
		expected      map[string]string
		expectedError error
	}{
		{
			name: "returns a map",
			s:    "app=nginx,valid=yes",
			expected: map[string]string{
				"app":   "nginx",
				"valid": "yes",
			},
			expectedError: nil,
		},
		{
			name:          "returns nil",
			s:             "",
			expected:      nil,
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := parsePodLabels(test.s)
			assert.Equal(t, test.expected, actual)
			assert.Equal(t, test.expectedError, err)
		})
	}
}
