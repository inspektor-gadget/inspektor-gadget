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

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

const (
	ContainerRuntimeDocker     = "docker"
	ContainerRuntimeContainerd = "containerd"
	ContainerRuntimeCRIO       = "cri-o"
	timeout                    = 10
)

//var supportedContainerRuntimes = []string{ContainerRuntimeDocker, ContainerRuntimeContainerd, ContainerRuntimeCRIO}

var (
	integration = flag.Bool("integration", false, "run integration tests")
	//containerRuntime = flag.String("container-runtime", "", "allows to do validation for expected runtime in the tests")
	dnsTesterImage = flag.String("dnstester-image", "ghcr.io/inspektor-gadget/dnstester:latest", "dnstester container image")
	testComponent  = flag.String("test-component", "", "run tests for specific component")
)

var (
	containerRuntime string
	isDockerRuntime  bool
)

func testMain(m *testing.M) error {
	var err error

	containerRuntime, err = GetContainerRuntime()
	if err != nil {
		return fmt.Errorf("getting container runtime: %w", err)
	}

	isDockerRuntime = containerRuntime == ContainerRuntimeDocker

	if testComponent == nil {
		return errors.New("-test-component' must be specified")
	}

	switch *testComponent {
	case "ig":
		DefaultTestComponent = IgTestComponent
	case "ig-k8s":
		if os.Getenv("KUBECTL_GADGET") == "" {
			return errors.New("$KUBECTL_GADGET not set")
		}
		DefaultTestComponent = InspektorGadgetTestComponent
	default:
		return fmt.Errorf("invalid argument '-test-component': %q. Valid values: ig, inspektor-gadget", *testComponent)
	}

	return nil
}

func TestMain(m *testing.M) {
	flag.Parse()
	if !*integration {
		fmt.Println("Skipping integration test.")
		os.Exit(0)
	}

	err := testMain(m)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	fmt.Println("Start running tests:")
	os.Exit(m.Run())
}
