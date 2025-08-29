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

package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

var expectedYaml = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-advise-networkpolicy-client-network
  namespace: <CLIENT_NAMESPACE>
spec:
  egress:
  - ports:
    - port: 80
      protocol: TCP
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: <SERVER_NAMESPACE>
      podSelector:
        matchLabels:
          run: test-advise-networkpolicy-server
  podSelector:
    matchLabels:
      run: test-advise-networkpolicy-client
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-advise-networkpolicy-server-network
  namespace: <SERVER_NAMESPACE>
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: <CLIENT_NAMESPACE>
      podSelector:
        matchLabels:
          run: test-advise-networkpolicy-client
    ports:
    - port: 80
      protocol: TCP
  podSelector:
    matchLabels:
      run: test-advise-networkpolicy-server
  policyTypes:
  - Ingress
  - Egress`

func TestAdviseNetworkpolicyGadget(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent != utils.KubectlGadgetTestComponent {
		t.Skip("This gadget is only for kubectl-gadget")
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")

	serverNs := utils.GenerateTestNamespaceName(t, "test-advise-networkpolicy")
	serverContainerName := "test-advise-networkpolicy-server"
	serverContainerImage := gadgettesting.NginxImage
	serverContainerOpts := []containers.ContainerOption{
		containers.WithContainerImage(serverContainerImage),
		containers.WithContainerNamespace(serverNs),
	}
	testServerContainer := containerFactory.NewContainer(
		serverContainerName,
		"nginx && sleep 10000",
		serverContainerOpts...,
	)

	testServerContainer.Start(t)
	t.Cleanup(func() {
		testServerContainer.Stop(t)
	})

	clientNs := utils.GenerateTestNamespaceName(t, "test-advise-networkpolicy")
	clientContainerName := "test-advise-networkpolicy-client"
	clientContainerImage := gadgettesting.BusyBoxImage
	clientContainerOpts := []containers.ContainerOption{
		containers.WithContainerImage(clientContainerImage),
		containers.WithContainerNamespace(clientNs),
	}
	testClientContainer := containerFactory.NewContainer(
		clientContainerName,
		fmt.Sprintf("while true; do sleep 0.5 && wget %s; done", testServerContainer.IP()),
		clientContainerOpts...,
	)

	testClientContainer.Start(t)
	t.Cleanup(func() {
		testClientContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	runnerOpts = append(runnerOpts,
		igrunner.WithFlags(fmt.Sprintf("-n=%s,%s", serverNs, clientNs), "--timeout=5"),
		igrunner.WithOutputMode("advise"))
	testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(serverNs, clientNs)))

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedYaml = strings.ReplaceAll(expectedYaml, "<SERVER_NAMESPACE>", serverNs)
			expectedYaml = strings.ReplaceAll(expectedYaml, "<CLIENT_NAMESPACE>", clientNs)
			yamlExpectedArr := strings.Split(expectedYaml, "---")
			yamlActualArr := strings.Split(output, "---")

			require.Equal(t, len(yamlExpectedArr), len(yamlActualArr), "number of policies")

			assert.YAMLEq(t, yamlExpectedArr[0], yamlActualArr[0], "first policy")
			assert.YAMLEq(t, yamlExpectedArr[1], yamlActualArr[1], "second policy")
		},
	))

	adviseNetworkPolicyCmd := igrunner.New("advise_networkpolicy", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{adviseNetworkPolicyCmd}, t, testingOpts...)
}
