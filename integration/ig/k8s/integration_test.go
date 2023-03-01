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
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

const (
	ContainerRuntimeDocker     = "docker"
	ContainerRuntimeContainerd = "containerd"
	ContainerRuntimeCRIO       = "cri-o"
)

var supportedContainerRuntimes = []string{ContainerRuntimeDocker, ContainerRuntimeContainerd, ContainerRuntimeCRIO}

var (
	integration      = flag.Bool("integration", false, "run integration tests")
	containerRuntime = flag.String("container-runtime", "", "allows to do validation for expected runtime in the tests")
)

func init() {
	DefaultTestComponent = IgTestComponent
}

func TestMain(m *testing.M) {
	flag.Parse()
	if !*integration {
		fmt.Println("Skipping integration test.")
		os.Exit(0)
	}

	if *containerRuntime == "" {
		fmt.Println("Error: '-container-runtime' must be specified")
		os.Exit(1)
	}

	found := false
	for _, val := range supportedContainerRuntimes {
		if *containerRuntime == val {
			found = true
			break
		}
	}

	if !found {
		fmt.Fprintf(os.Stderr, "Error: invalid argument '-container-runtime': %q. Valid values: %s\n",
			*containerRuntime, strings.Join(supportedContainerRuntimes, ", "))
		os.Exit(1)
	}

	fmt.Println("Start running tests:")
	os.Exit(m.Run())
}
