// Copyright 2019-2023 The Inspektor Gadget authors
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
	"fmt"
	"testing"

	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestAdviseNetworkpolicy(t *testing.T) {
	nsServer := GenerateTestNamespaceName("test-advise-networkpolicy-server")
	nsClient := GenerateTestNamespaceName("test-advise-networkpolicy-client")

	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	commands := []*Command{
		CreateTestNamespaceCommand(nsServer),
		BusyboxPodRepeatCommand(
			nsServer,
			// Dual stack socket
			"nc -lk -p 9090 -e /bin/cat",
		),
		{
			Name:           "CreateService",
			Cmd:            fmt.Sprintf("kubectl expose -n %s pod test-pod --port 9090", nsServer),
			ExpectedRegexp: "service/test-pod exposed",
		},
		WaitUntilTestPodReadyCommand(nsServer),
		CreateTestNamespaceCommand(nsClient),
		BusyboxPodRepeatCommand(
			nsClient,
			// IPv4 socket
			fmt.Sprintf("echo ok | nc -w 1 test-pod.%s.svc.cluster.local 9090 || true", nsServer),
		),
		WaitUntilTestPodReadyCommand(nsClient),
		{
			Name: "RunNetworkPolicyMonitorClient",
			Cmd:  fmt.Sprintf(`$KUBECTL_GADGET advise network-policy monitor -n %s --timeout 5 --output - | tee ./networktrace-client.log`, nsClient),
			ValidateOutput: func(t *testing.T, output string) {
				expectedEntry := &networkTypes.Event{
					Event:     BuildBaseEventK8s(nsClient, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					Comm:      "nc",
					Uid:       0,
					Gid:       0,
					PktType:   "OUTGOING",
					Proto:     "TCP",
					PodLabels: map[string]string{"run": "test-pod"},
					Port:      9090,
					DstEndpoint: eventtypes.L3Endpoint{
						Kind:      eventtypes.EndpointKindService,
						Namespace: nsServer,
						Name:      "test-pod",
						PodLabels: map[string]string{"run": "test-pod"},
					},
				}

				expectedEntry.K8s.ContainerName = ""

				normalize := func(e *networkTypes.Event) {
					e.Timestamp = 0
					e.Pid = 0
					e.Tid = 0
					e.PodIP = ""
					e.DstEndpoint.Addr = ""
					e.DstEndpoint.Version = 0
					e.PodHostIP = ""
					e.NetNsID = 0
					e.MountNsID = 0

					e.K8s.Node = ""
					e.K8s.ContainerName = ""
					// TODO: Verify container runtime and container name
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
					e.Runtime.ContainerID = ""
					e.Runtime.ContainerImageDigest = ""
				}

				ExpectEntriesToMatch(t, output, normalize, expectedEntry)
			},
		},
		{
			Name: "RunNetworkPolicyMonitorServer",
			Cmd:  fmt.Sprintf(`$KUBECTL_GADGET advise network-policy monitor -n %s --timeout 5 --output - | tee ./networktrace-server.log`, nsServer),
			ValidateOutput: func(t *testing.T, output string) {
				// Docker bridge does not preserve source IP :-(
				// https://github.com/kubernetes/minikube/issues/11211
				// Skip this test step if docker is detected
				if isDockerRuntime {
					return
				}

				expectedEntry := &networkTypes.Event{
					Event: BuildBaseEventK8s(nsServer, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					// The socket enricher can find the correct "comm" because it supports dual stack sockets
					Comm:      "nc",
					Uid:       0,
					Gid:       0,
					PktType:   "HOST",
					Proto:     "TCP",
					PodLabels: map[string]string{"run": "test-pod"},
					Port:      9090,
					DstEndpoint: eventtypes.L3Endpoint{
						Kind:      eventtypes.EndpointKindPod,
						Namespace: nsClient,
						Name:      "test-pod",
						PodLabels: map[string]string{"run": "test-pod"},
					},
				}

				expectedEntry.K8s.ContainerName = ""

				normalize := func(e *networkTypes.Event) {
					e.Timestamp = 0
					e.Pid = 0
					e.Tid = 0
					e.PodIP = ""
					e.DstEndpoint.Addr = ""
					e.DstEndpoint.Version = 0
					e.PodHostIP = ""
					e.NetNsID = 0
					e.MountNsID = 0

					e.K8s.Node = ""
					e.K8s.ContainerName = ""
					// TODO: Verify container runtime and container name
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
					e.Runtime.ContainerID = ""
					e.Runtime.ContainerImageDigest = ""
				}

				ExpectEntriesToMatch(t, output, normalize, expectedEntry)
			},
		},
		{
			Name: "RunNetworkPolicyReportClient",
			Cmd:  "$KUBECTL_GADGET advise network-policy report --input ./networktrace-client.log",
			ExpectedRegexp: fmt.Sprintf(`(?s)apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: test-pod-network
  namespace: %s
spec:
  egress:
  - ports:
    - port: 9090
      protocol: TCP
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: %s
      podSelector:
        matchLabels:
          run: test-pod
  - ports:
    - port: 53
      protocol: UDP
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: (kube-system|openshift-dns)
      podSelector:
        matchLabels:
          .*(kubernetes.io/name: CoreDNS|k8s-app: kube-dns|dns.operator.openshift.io/.*: default).*
  podSelector:
    matchLabels:
      run: test-pod
  policyTypes:
  - Ingress
  - Egress`, nsClient, nsServer),
		},
		{
			Name: "RunNetworkPolicyReportServer",
			Cmd: `$KUBECTL_GADGET advise network-policy report --input ./networktrace-server.log
				kubectl get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}'|grep -q docker && echo SKIP_TEST || true`,
			ExpectedRegexp: fmt.Sprintf(`(?s)SKIP_TEST|apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: test-pod-network
  namespace: %s
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: %s
      podSelector:
        matchLabels:
          run: test-pod
    ports:
    - port: 9090
      protocol: TCP
  podSelector:
    matchLabels:
      run: test-pod
  policyTypes:
  - Ingress
  - Egress`, nsServer, nsClient),
		},
		DeleteTestNamespaceCommand(nsClient),
		DeleteTestNamespaceCommand(nsServer),
		{
			Name:    "CleanupLogFiles",
			Cmd:     "rm -f networktrace-client.log networktrace-server.log",
			Cleanup: true,
		},
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(nsServer, nsClient)))
}
