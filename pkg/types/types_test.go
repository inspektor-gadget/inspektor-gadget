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

func TestBasicEcsMetadataIsEnriched(t *testing.T) {
	tests := []struct {
		name     string
		metadata BasicEcsMetadata
		expected bool
	}{
		{
			name: "fully enriched",
			metadata: BasicEcsMetadata{
				ClusterName:   "my-cluster",
				TaskFamily:    "my-task",
				ContainerName: "my-container",
			},
			expected: true,
		},
		{
			name: "missing cluster name",
			metadata: BasicEcsMetadata{
				TaskFamily:    "my-task",
				ContainerName: "my-container",
			},
			expected: false,
		},
		{
			name: "missing task family",
			metadata: BasicEcsMetadata{
				ClusterName:   "my-cluster",
				ContainerName: "my-container",
			},
			expected: false,
		},
		{
			name: "missing container name",
			metadata: BasicEcsMetadata{
				ClusterName: "my-cluster",
				TaskFamily:  "my-task",
			},
			expected: false,
		},
		{
			name:     "empty metadata",
			metadata: BasicEcsMetadata{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.metadata.IsEnriched())
		})
	}
}

func TestEcsMetadataJSON(t *testing.T) {
	input := `{
		"clusterName": "production-cluster",
		"taskFamily": "web-app",
		"taskRevision": "5",
		"serviceName": "web-service",
		"containerName": "nginx",
		"launchType": "FARGATE",
		"clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/production-cluster",
		"taskArn": "arn:aws:ecs:us-east-1:123456789012:task/production-cluster/abc123",
		"taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/web-app:5",
		"containerArn": "arn:aws:ecs:us-east-1:123456789012:container/xyz789",
		"availabilityZone": "us-east-1a",
		"containerInstance": "arn:aws:ecs:us-east-1:123456789012:container-instance/abc"
	}`

	expected := &EcsMetadata{
		BasicEcsMetadata: BasicEcsMetadata{
			ClusterName:   "production-cluster",
			TaskFamily:    "web-app",
			TaskRevision:  "5",
			ServiceName:   "web-service",
			ContainerName: "nginx",
			LaunchType:    "FARGATE",
		},
		ClusterARN:        "arn:aws:ecs:us-east-1:123456789012:cluster/production-cluster",
		TaskARN:           "arn:aws:ecs:us-east-1:123456789012:task/production-cluster/abc123",
		TaskDefinitionARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/web-app:5",
		ContainerARN:      "arn:aws:ecs:us-east-1:123456789012:container/xyz789",
		AvailabilityZone:  "us-east-1a",
		ContainerInstance: "arn:aws:ecs:us-east-1:123456789012:container-instance/abc",
	}

	var actual EcsMetadata
	err := json.Unmarshal([]byte(input), &actual)

	assert.NoError(t, err)
	assert.Equal(t, expected.ClusterName, actual.ClusterName)
	assert.Equal(t, expected.TaskFamily, actual.TaskFamily)
	assert.Equal(t, expected.TaskRevision, actual.TaskRevision)
	assert.Equal(t, expected.ServiceName, actual.ServiceName)
	assert.Equal(t, expected.ContainerName, actual.ContainerName)
	assert.Equal(t, expected.LaunchType, actual.LaunchType)
	assert.Equal(t, expected.ClusterARN, actual.ClusterARN)
	assert.Equal(t, expected.TaskARN, actual.TaskARN)
	assert.Equal(t, expected.TaskDefinitionARN, actual.TaskDefinitionARN)
	assert.Equal(t, expected.ContainerARN, actual.ContainerARN)
	assert.Equal(t, expected.AvailabilityZone, actual.AvailabilityZone)
	assert.Equal(t, expected.ContainerInstance, actual.ContainerInstance)
}

func TestCommonDataWithEcs(t *testing.T) {
	input := `{
		"runtime": {
			"runtimeName": "containerd",
			"containerId": "abc123",
			"containerName": "nginx"
		},
		"ecs": {
			"clusterName": "prod-cluster",
			"taskFamily": "web-task",
			"containerName": "nginx"
		}
	}`

	var actual CommonData
	err := json.Unmarshal([]byte(input), &actual)

	assert.NoError(t, err)
	assert.Equal(t, "containerd", string(actual.Runtime.RuntimeName))
	assert.Equal(t, "prod-cluster", actual.Ecs.ClusterName)
	assert.Equal(t, "web-task", actual.Ecs.TaskFamily)
	assert.True(t, actual.Ecs.IsEnriched())
}
