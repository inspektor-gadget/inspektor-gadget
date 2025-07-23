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

package hookservice

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/hook-service/api"
)

// Helper function to extract annotations from OCI config
func extractOCIAnnotations(ociConfig string) (map[string]string, error) {
	var config struct {
		Annotations map[string]string `json:"annotations"`
	}

	if err := json.Unmarshal([]byte(ociConfig), &config); err != nil {
		return nil, err
	}

	return config.Annotations, nil
}

// Helper function to extract container metadata from OCI config
func extractContainerMetadata(ociConfig string) (name, podName, namespace string, err error) {
	annotations, err := extractOCIAnnotations(ociConfig)
	if err != nil {
		return "", "", "", err
	}

	name = annotations["io.kubernetes.cri.container-name"]
	podName = annotations["io.kubernetes.cri.sandbox-name"]
	namespace = annotations["io.kubernetes.cri.sandbox-namespace"]

	return name, podName, namespace, nil
}

func TestHookServer(t *testing.T) {
	// Initialize container collection with OCI config enrichment
	var cc containercollection.ContainerCollection
	cc.Initialize([]containercollection.ContainerCollectionOption{
		containercollection.WithOCIConfigEnrichment(),
	}...)
	defer cc.Close()

	// Create hook server
	server := NewServer(&cc)
	require.NotNil(t, server, "Server should not be nil")

	ctx := context.Background()

	// Test data for multiple containers
	testContainers := []*pb.ContainerDefinition{
		{
			Id:        "container1",
			Name:      "test-container-1",
			Namespace: "default",
			Podname:   "test-pod-1",
			Pid:       1001,
			Labels: []*pb.Label{
				{Key: "app", Value: "web"},
				{Key: "version", Value: "1.0"},
			},
		},
		{
			Id:        "container2",
			Name:      "test-container-2",
			Namespace: "kube-system",
			Podname:   "test-pod-2",
			Pid:       1002,
			Labels: []*pb.Label{
				{Key: "app", Value: "db"},
				{Key: "version", Value: "2.0"},
			},
		},
		{
			// Test without labels
			Id:        "container3",
			Name:      "test-container-3",
			Namespace: "monitoring",
			Podname:   "test-pod-3",
			Pid:       1003,
		},
		{
			// Container as OCI hook would add it (Use containerd annotations style)
			Id:        "oci-container-123",
			Pid:       1004,
			OciConfig: `{"annotations":{"io.kubernetes.cri.container-type":"container","io.kubernetes.cri.container-name":"test-app","io.kubernetes.cri.sandbox-name":"test-pod-oci","io.kubernetes.cri.sandbox-namespace":"default"}}`,
		},
	}

	// Section 1: Add containers
	for i, containerDef := range testContainers {
		t.Logf("Adding container %d: %s", i+1, containerDef.Id)

		// Add container
		resp, err := server.AddContainer(ctx, containerDef)
		require.NoError(t, err, "Failed to add container %s", containerDef.Id)
		require.NotNil(t, resp, "Response should not be nil")

		// Verify container was added to collection
		container := cc.GetContainer(containerDef.Id)
		require.NotNil(t, container, "Container %s should exist in collection", containerDef.Id)

		// For OCI containers, extract metadata from OCI config to compare against enriched values
		var expectedName, expectedPodName, expectedNamespace string
		if containerDef.OciConfig != "" {
			require.Equal(t, containerDef.OciConfig, container.OciConfig, "OCI config should match")

			var err error
			expectedName, expectedPodName, expectedNamespace, err = extractContainerMetadata(containerDef.OciConfig)
			require.NoError(t, err, "Failed to extract metadata from OCI config")
		} else {
			expectedName = containerDef.Name
			expectedPodName = containerDef.Podname
			expectedNamespace = containerDef.Namespace
		}

		require.Equal(t, containerDef.Id, container.Runtime.ContainerID)
		require.Equal(t, containerDef.Pid, container.Runtime.ContainerPID)
		require.Equal(t, expectedName, container.K8s.ContainerName)
		require.Equal(t, expectedNamespace, container.K8s.Namespace)
		require.Equal(t, expectedPodName, container.K8s.PodName)

		// Verify labels if set
		if len(containerDef.Labels) > 0 {
			require.NotNil(t, container.K8s.PodLabels, "Pod labels should not be nil")
			require.Equal(t, len(containerDef.Labels), len(container.K8s.PodLabels))
			for _, label := range containerDef.Labels {
				require.Equal(t, label.Value, container.K8s.PodLabels[label.Key])
			}
		} else {
			require.Nil(t, container.K8s.PodLabels, "Pod labels should be nil")
		}
	}

	// Section 2: Error cases for AddContainer
	// Test empty container ID
	_, err := server.AddContainer(ctx, &pb.ContainerDefinition{
		Id:   "",
		Name: "test-container",
	})
	require.Error(t, err, "Should fail with empty container ID")

	// Test duplicate container
	_, err = server.AddContainer(ctx, &pb.ContainerDefinition{
		Id:   "container1", // Already exists
		Name: "duplicate-container",
	})
	require.Error(t, err, "Should fail with duplicate container ID")

	// Section 3: Remove containers
	// Remove container2 first
	resp, err := server.RemoveContainer(ctx, &pb.ContainerDefinition{
		Id: "container2",
	})
	require.NoError(t, err, "Failed to remove container2")
	require.NotNil(t, resp, "Response should not be nil")

	// Verify container was removed
	container := cc.GetContainer("container2")
	require.Nil(t, container, "Container2 should be removed from collection")

	// Remove remaining containers
	for _, containerDef := range []*pb.ContainerDefinition{
		{Id: "container1"},
		{Id: "container3"},
		{Id: "oci-container-123"},
	} {
		t.Logf("Removing container: %s", containerDef.Id)

		resp, err := server.RemoveContainer(ctx, containerDef)
		require.NoError(t, err, "Failed to remove container %s", containerDef.Id)
		require.NotNil(t, resp, "Response should not be nil")

		// Verify container was removed
		container := cc.GetContainer(containerDef.Id)
		require.Nil(t, container, "Container %s should be removed from collection", containerDef.Id)
	}

	// Section 4: Error cases for RemoveContainer
	// Test empty container ID
	_, err = server.RemoveContainer(ctx, &pb.ContainerDefinition{
		Id: "",
	})
	require.Error(t, err, "Should fail with empty container ID")

	// Test non-existent container
	_, err = server.RemoveContainer(ctx, &pb.ContainerDefinition{
		Id: "nonexistent",
	})
	require.Error(t, err, "Should fail with non-existent container")

	// Section 5: Verify collection is empty after all removals
	for _, containerDef := range testContainers {
		container := cc.GetContainer(containerDef.Id)
		require.Nil(t, container, "Container %s should not exist after removal", containerDef.Id)
	}
}
