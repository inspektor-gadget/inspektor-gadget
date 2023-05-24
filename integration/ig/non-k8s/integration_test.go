// Copyright 2022-2023 The Inspektor Gadget authors
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
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

var (
	containerFactory ContainerFactory
	// flags
	integration    = flag.Bool("integration", false, "run integration tests")
	dnsTesterImage = flag.String("dnstester-image", "ghcr.io/inspektor-gadget/dnstester:latest", "dnstester container image")
	runtime        = flag.String("runtime", "docker", "which runtime to use (docker, containerd)")
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

	var err error
	containerFactory, err = NewContainerFactory(*runtime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Println("Start running tests:")
	os.Exit(m.Run())
}
