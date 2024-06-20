// Copyright 2022 The Inspektor Gadget authors
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

package integration

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var cmpIgnoreUnexported = cmpopts.IgnoreUnexported(
	containercollection.Container{},
	containercollection.K8sMetadata{},
)

type CommonDataOption func(commonData *eventtypes.CommonData)

// WithRuntimeMetadata sets the runtime and container name in the common data.
// Notice the container name is taken from the Kubernetes metadata.
func WithRuntimeMetadata(runtime string) CommonDataOption {
	return func(commonData *eventtypes.CommonData) {
		commonData.Runtime.RuntimeName = eventtypes.String2RuntimeName(runtime)
		commonData.Runtime.ContainerName = commonData.K8s.ContainerName
	}
}

// WithContainerImageName sets the ContainerImageName to facilitate the tests
func WithContainerImageName(imageName string, isDockerRuntime bool) CommonDataOption {
	return func(commonData *eventtypes.CommonData) {
		if !isDockerRuntime {
			commonData.Runtime.ContainerImageName = imageName
		}
	}
}

// WithPodLabels sets the PodLabels to facilitate the tests
func WithPodLabels(podName string, namespace string, enable bool) CommonDataOption {
	return func(commonData *eventtypes.CommonData) {
		if enable {
			commonData.K8s.PodLabels = map[string]string{
				"run": podName,
			}
		}
	}
}

func BuildCommonData(namespace string, options ...CommonDataOption) eventtypes.CommonData {
	e := eventtypes.CommonData{
		K8s: eventtypes.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: namespace,
				// Pod and Container name are defined by BusyboxPodCommand.
				PodName:       "test-pod",
				ContainerName: "test-pod",
			},
		},
		// TODO: Include the Node
	}
	for _, option := range options {
		option(&e)
	}
	return e
}

func BuildCommonDataK8s(namespace string, options ...CommonDataOption) eventtypes.CommonData {
	e := BuildCommonData(namespace, options...)
	WithPodLabels("test-pod", namespace, true)(&e)
	return e
}

func BuildBaseEvent(namespace string, options ...CommonDataOption) eventtypes.Event {
	e := eventtypes.Event{
		Type:       eventtypes.NORMAL,
		CommonData: BuildCommonData(namespace),
	}
	for _, option := range options {
		option(&e.CommonData)
	}
	return e
}

func BuildBaseEventK8s(namespace string, options ...CommonDataOption) eventtypes.Event {
	e := BuildBaseEvent(namespace, options...)
	WithPodLabels("test-pod", namespace, true)(&e.CommonData)
	return e
}

func GetTestPodIP(t *testing.T, ns string, podname string) string {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting pod ip: %s", stderr.String())
	return string(r)
}

func GetPodIPsFromLabel(t *testing.T, ns string, label string) []string {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", "-l", label, "-o", "jsonpath={.items[*].status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting pods ips from label: %s", stderr.String())
	return strings.Split(string(r), " ")
}

func GetPodNode(t *testing.T, ns string, podname string) string {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.spec.nodeName}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting pod node: %s", stderr.String())
	return string(r)
}

func GetPodUID(t *testing.T, ns, podname string) string {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.metadata.uid}")
	r, err := cmd.Output()
	require.NoError(t, err, "getting UID of %s/%s: %s", ns, podname, r)
	return string(r)
}

func CheckNamespace(ns string) bool {
	cmd := exec.Command("kubectl", "get", "ns", ns)
	return cmd.Run() == nil
}

// IsDockerRuntime checks whether the container runtime of the first node in the Kubernetes cluster is Docker or not.
func IsDockerRuntime(t *testing.T) bool {
	cmd := exec.Command("kubectl", "get", "node", "-o", "jsonpath={.items[0].status.nodeInfo.containerRuntimeVersion}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting container runtime: %s", stderr.String())
	ret := string(r)

	return strings.Contains(ret, "docker")
}

// GetContainerRuntime returns the container runtime the cluster is using.
func GetContainerRuntime() (string, error) {
	cmd := exec.Command("kubectl", "get", "node", "-o", "jsonpath={.items[0].status.nodeInfo.containerRuntimeVersion}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getting container runtime: %w, %s", err, stderr.String())
	}

	ret := string(r)
	parts := strings.Split(ret, ":")
	if len(parts) < 1 {
		return "", fmt.Errorf("unexpected container runtime version: %s", ret)
	}
	return parts[0], nil
}

// GetIPVersion returns the version of the IP, 4 or 6. It makes the test fail in case of error.
// Based on https://stackoverflow.com/a/48519490
func GetIPVersion(t *testing.T, address string) uint8 {
	if strings.Count(address, ":") < 2 {
		return 4
	} else if strings.Count(address, ":") >= 2 {
		return 6
	}
	t.Fatalf("Failed to determine IP version for address %s", address)
	return 0
}

func StartRegistry(t *testing.T, name string) testutils.Container {
	t.Helper()

	c := testutils.NewDockerContainer(name, "registry serve /etc/docker/registry/config.yml",
		testutils.WithImage("registry:2"),
		testutils.WithoutWait(),
		testutils.WithPortBindings(nat.PortMap{
			"5000/tcp": []nat.PortBinding{{HostIP: "127.0.0.1"}},
		}),
	)
	c.Start(t)
	return c
}
