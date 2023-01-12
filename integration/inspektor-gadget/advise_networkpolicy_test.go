// Copyright 2019-2022 The Inspektor Gadget authors
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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestAdviseNetworkpolicy(t *testing.T) {
	nsServer := GenerateTestNamespaceName("test-advise-networkpolicy-server")
	nsClient := GenerateTestNamespaceName("test-advise-networkpolicy-client")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(nsServer),
		BusyboxPodRepeatCommand(nsServer, "nc -lk -p 9090 -e /bin/cat"),
		{
			Name:           "CreateService",
			Cmd:            fmt.Sprintf("kubectl expose -n %s pod test-pod --port 9090", nsServer),
			ExpectedRegexp: "service/test-pod exposed",
		},
		WaitUntilTestPodReadyCommand(nsServer),
		CreateTestNamespaceCommand(nsClient),
		BusyboxPodRepeatCommand(nsClient, fmt.Sprintf("echo ok | nc -w 1 test-pod.%s.svc.cluster.local 9090 || true", nsServer)),
		WaitUntilTestPodReadyCommand(nsClient),
		{
			Name: "RunNetworkPolicyMonitorClient",
			Cmd: fmt.Sprintf(`$KUBECTL_GADGET advise network-policy monitor -n %s --output ./networktrace-client.log &
					sleep 10
					kill $!
					head networktrace-client.log | sort | uniq`, nsClient),
			ExpectedRegexp: fmt.Sprintf(`{"node":".*","namespace":"%s","pod":"test-pod","container":"test-pod","timestamp":.*,"type":"normal","pktType":"OUTGOING","proto":"tcp","port":9090,"podHostIP":".*","podIP":".*","podLabels":{"run":"test-pod"},"remoteKind":"svc","remoteAddr":".*","remoteName":"test-pod","remoteNamespace":"%s","remoteLabels":{"run":"test-pod"}}`, nsClient, nsServer),
		},
		{
			// Docker bridge does not preserve source IP :-(
			// https://github.com/kubernetes/minikube/issues/11211
			// Skip this command with SKIP_TEST if docker is detected
			Name: "RunNetworkPolicyMonitorServer",
			Cmd: fmt.Sprintf(`$KUBECTL_GADGET advise network-policy monitor -n %s --output ./networktrace-server.log &
					sleep 10
					kill $!
					head networktrace-server.log | sort | uniq
					kubectl get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}'|grep -q docker && echo SKIP_TEST || true`, nsServer),
			ExpectedRegexp: fmt.Sprintf(`SKIP_TEST|{"node":".*","namespace":"%s","pod":"test-pod","container":"test-pod","timestamp":.*,"type":"normal","pktType":"HOST","proto":"tcp","port":9090,"podHostIP":".*","podIP":".*","podLabels":{"run":"test-pod"},"remoteKind":"pod","remoteAddr":".*","remoteName":"test-pod","remoteNamespace":"%s","remoteLabels":{"run":"test-pod"}}`, nsServer, nsClient),
		},
		{
			Name: "RunNetworkPolicyReportClient",
			Cmd:  "$KUBECTL_GADGET advise network-policy report --input ./networktrace-client.log",
			ExpectedRegexp: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
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
          (k8s-app: kube-dns|dns.operator.openshift.io/daemonset-dns: default)
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
			ExpectedRegexp: fmt.Sprintf(`SKIP_TEST|apiVersion: networking.k8s.io/v1
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

	RunTestSteps(commands, t)
}
