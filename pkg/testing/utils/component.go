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
	"os"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type TestComponent string

const (
	// Used to test gadget using ig for container running locally
	IgLocalTestComponent TestComponent = "ig-local"

	// Used to test gadget using ig for container running in k8s
	IgK8sTestComponent TestComponent = "ig-k8s"

	// Used to test gadget using kubectl-gadget for container running in k8s
	KubectlGadgetTestComponent TestComponent = "kubectl-gadget"
)

var (
	Runtime              = eventtypes.RuntimeNameDocker.String()
	ContainerRuntime     = Runtime
	CurrentTestComponent = IgLocalTestComponent
)

func InitTest(t *testing.T) {
	if os.Getenv("IG_RUNTIME") != "" {
		Runtime = os.Getenv("IG_RUNTIME")
		ContainerRuntime = Runtime

		if Runtime == containers.RuntimeKubernetes {
			// Get container runtime used in the cluster
			ContainerRuntime = GetContainerRuntime(t)

			if CurrentTestComponent == IgLocalTestComponent {
				CurrentTestComponent = IgK8sTestComponent
			}
		}
	}

	if strings.Contains(os.Getenv("IG_PATH"), string(KubectlGadgetTestComponent)) {
		CurrentTestComponent = KubectlGadgetTestComponent

		if Runtime != containers.RuntimeKubernetes {
			t.Fatalf("invalid value of runtime for kubectl-gadget. Valid value is %s", containers.RuntimeKubernetes)
		}
	}
}
