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
)

var cmpIgnoreUnexported = cmpopts.IgnoreUnexported(
	containercollection.Container{},
	containercollection.K8sMetadata{},
)

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
