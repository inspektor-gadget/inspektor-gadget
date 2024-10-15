// Copyright 2019-2024 The Inspektor Gadget authors
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

package utils

import (
	"bytes"
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/constraints"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var (
	seed int64      = time.Now().UTC().UnixNano()
	r    *rand.Rand = rand.New(rand.NewSource(seed))
)

type CommonDataOption func(commonData *eventtypes.CommonData)

// WithContainerImageName sets the ContainerImageName to facilitate the tests
func WithContainerImageName(imageName string) CommonDataOption {
	return func(commonData *eventtypes.CommonData) {
		if CurrentTestComponent == IgLocalTestComponent || !IsDockerRuntime() {
			commonData.Runtime.ContainerImageName = imageName
		}
	}
}

// WithContainerID sets the ContainerID to facilitate the tests
func WithContainerID(containerID string) CommonDataOption {
	return func(commonData *eventtypes.CommonData) {
		commonData.Runtime.ContainerID = containerID
	}
}

// WithK8sNamespace sets the Namepsace to facilitate the tests
func WithK8sNamespace(namespace string) CommonDataOption {
	return func(commonData *eventtypes.CommonData) {
		commonData.K8s.Namespace = namespace
	}
}

func BuildCommonData(containerName string, options ...CommonDataOption) eventtypes.CommonData {
	var e eventtypes.CommonData

	switch CurrentTestComponent {
	case IgLocalTestComponent:
		e = eventtypes.CommonData{
			Runtime: eventtypes.BasicRuntimeMetadata{
				RuntimeName:   eventtypes.String2RuntimeName(ContainerRuntime),
				ContainerName: containerName,
			},
		}
	case KubectlGadgetTestComponent:
		e = eventtypes.CommonData{
			K8s: eventtypes.K8sMetadata{
				BasicK8sMetadata: eventtypes.BasicK8sMetadata{
					// Pod and Container name are defined by BusyboxPodCommand.
					// Note the Pod is also assigned the containerName
					PodName:       containerName,
					ContainerName: containerName,
				},
			},
			// TODO: Include the Node
		}
	}

	for _, option := range options {
		option(&e)
	}
	return e
}

func BuildEndpointK8sData(kind, name, namespace, labels string) K8s {
	if CurrentTestComponent != KubectlGadgetTestComponent {
		return K8s{}
	}
	return K8s{
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

func NormalizeCommonData(e *eventtypes.CommonData) {
	// The container image digest is not currently enriched for Docker containers:
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/2365
	// It's enriched for other runtimes like containerd and cri-o, but our
	// testing framework doesn't provide any way to get this information, so
	// ignore this field for now.
	e.Runtime.ContainerImageDigest = ""

	if CurrentTestComponent == KubectlGadgetTestComponent {
		e.K8s.Node = ""
		// TODO: Verify container runtime and container name
		e.Runtime.RuntimeName = ""
		e.Runtime.ContainerName = ""
	}
}

func IsDockerRuntime() bool {
	return ContainerRuntime == eventtypes.RuntimeNameDocker.String()
}

// PrintLogsFn returns a function that print logs in case the test fails.
func PrintLogsFn(namespaces ...string) func(t *testing.T) {
	return func(t *testing.T) {
		if !t.Failed() {
			return
		}

		if CurrentTestComponent == KubectlGadgetTestComponent {
			t.Logf("Inspektor Gadget pod logs:")
			t.Logf(getPodLogs("gadget"))
		}

		for _, ns := range namespaces {
			t.Logf("Logs in namespace %s:", ns)
			t.Logf(getPodLogs(ns))
		}
	}
}

// getPodLogs returns a string with the logs of all pods in namespace ns
func getPodLogs(ns string) string {
	if CurrentTestComponent != KubectlGadgetTestComponent {
		return ""
	}

	var sb strings.Builder
	logCommands := []string{
		fmt.Sprintf("kubectl get pods -n %s -o wide", ns),
		fmt.Sprintf(`for pod in $(kubectl get pods -n %[1]s -o name); do
			kubectl logs -n %[1]s $pod --previous;
			kubectl logs -n %[1]s $pod;
		done`, ns),
	}

	for _, c := range logCommands {
		cmd := exec.Command("/bin/sh", "-xc", c)
		output, err := cmd.CombinedOutput()
		if err != nil {
			sb.WriteString(fmt.Sprintf("Error: failed to run log command: %s, %s\n", cmd.String(), err))
			continue
		}
		sb.WriteString(string(output))
	}

	return sb.String()
}

// GetContainerRuntime returns the container runtime the cluster is using.
func GetContainerRuntime(t *testing.T) string {
	cmd := exec.Command("kubectl", "get", "node", "-o", "jsonpath={.items[0].status.nodeInfo.containerRuntimeVersion}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting container runtime: %s", stderr.String())

	ret := string(r)
	parts := strings.Split(ret, ":")
	require.GreaterOrEqual(t, len(parts), 1, "unexpected container runtime version")
	return parts[0]
}

// GenerateTestNamespaceName returns a string which can be used as unique
// namespace.
// The returned value is: namespace_parameter-random_integer.
func GenerateTestNamespaceName(t *testing.T, namespace string) string {
	t.Logf("Seed used: %d", seed)
	return fmt.Sprintf("%s-%d", namespace, r.Int())
}

const (
	NormalizedInt = 1
	NormalizedStr = "foo"
)

func NormalizeInt[T constraints.Integer](f *T) {
	var zero T

	if *f != zero {
		*f = T(NormalizedInt)
	}
}

func NormalizeString(f *string) {
	if *f != "" {
		*f = NormalizedStr
	}
}
