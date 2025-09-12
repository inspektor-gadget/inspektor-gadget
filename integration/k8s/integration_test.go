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

package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

const (
	ContainerRuntimeDocker     = "docker"
	ContainerRuntimeContainerd = "containerd"
	ContainerRuntimeCRIO       = "cri-o"
	timeout                    = 10
	maxRows                    = 999
	topTimeoutInSeconds        = 10
)

var (
	supportedK8sDistros = []string{
		K8sDistroAKSAzureLinux,
		K8sDistroAKSUbuntu,
		K8sDistroARO,
		K8sDistroMinikubeGH,
		K8sDistroEKSAmazonLinux,
		K8sDistroGKECOS,
	}
	containerRuntime string
	isDockerRuntime  bool
	isCrioRuntime    bool
)

var (
	integrationTest = flag.Bool("integration", false, "run integration tests")
	dnsTesterImage  = flag.String("dnstester-image", "ghcr.io/inspektor-gadget/dnstester:main", "dnstester container image")
	testComponent   = flag.String("test-component", "", "run tests for specific component")
	k8sArch         = flag.String("k8s-arch", "amd64", "allows to skip tests that are not supported on a given CPU architecture")
)

func initialize() error {
	var err error

	containerRuntime, err = GetContainerRuntime()
	if err != nil {
		return fmt.Errorf("getting container runtime: %w", err)
	}

	isDockerRuntime = containerRuntime == ContainerRuntimeDocker
	isCrioRuntime = containerRuntime == ContainerRuntimeCRIO

	switch *testComponent {
	case "ig":
		DefaultTestComponent = IgTestComponent
	case "inspektor-gadget":
		DefaultTestComponent = InspektorGadgetTestComponent
	default:
		return fmt.Errorf("invalid argument '-test-component': %q. Valid values: ig, inspektor-gadget", *testComponent)
	}

	if *k8sDistro != "" {
		found := slices.Contains(supportedK8sDistros, *k8sDistro)

		if !found {
			return fmt.Errorf("Error: invalid argument '-k8s-distro': %q. Valid values: %s\n",
				*k8sDistro, strings.Join(supportedK8sDistros, ", "))
		}
	}

	return nil
}

func TestMain(m *testing.M) {
	flag.Parse()
	if !*integrationTest {
		fmt.Println("Skipping integration test.")
		os.Exit(0)
	}

	err := initialize()
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	switch DefaultTestComponent {
	case IgTestComponent:
		os.Exit(testMainIG(m))
	case InspektorGadgetTestComponent:
		os.Exit(testMainInspektorGadget(m))
	}
}
