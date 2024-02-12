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

	seccompauditTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestAuditSeccomp(t *testing.T) {
	ns := GenerateTestNamespaceName("test-audit-seccomp")
	t.Parallel()

	// TODO: Handle it once we support getting container image name from docker
	isDockerRuntime := IsDockerRuntime(t)

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		{
			Name: "CreateSeccompProfile",
			Cmd: fmt.Sprintf(`
				kubectl apply -f - <<EOF
# This yaml template is used to copy a seccomp profile to all nodes on the cluster.
apiVersion: v1
kind: ConfigMap
metadata:
  name: myseccompprofile
  namespace: %[1]s
data:
  ig-test-profile.json: |
    {
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [
            {
                "names": [
                    "unshare"
                ],
                "action": "SCMP_ACT_KILL"
            },
            {
                "names": [
                    "mkdir"
                ],
                "action": "SCMP_ACT_LOG"
            }
        ]
    }
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: seccomp-copier
  namespace: %[1]s
spec:
  selector:
    matchLabels:
      name: seccomp-copier
  template:
    metadata:
      labels:
        name: seccomp-copier
    spec:
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
        effect: NoSchedule
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: NoSchedule
      containers:
      - name: copier
        image: busybox:latest
        command: [ "sh", "-c", "cp /sourceprofile/ig-test-profile.json /seccomp/ig-test-profile.json ; sleep inf"]
        volumeMounts:
        - name: seccomp
          mountPath: /seccomp/
        - name: sourceprofile
          mountPath: /sourceprofile/
      terminationGracePeriodSeconds: 1
      volumes:
      - name: seccomp
        hostPath:
          path: /var/lib/kubelet/seccomp/
      - name: sourceprofile
        configMap:
          name: myseccompprofile
EOF
`, ns),
			ExpectedRegexp: fmt.Sprintf("daemonset.apps/seccomp-copier created"),
		},
		{
			Name: "WaitForDaemonSet",
			Cmd:  fmt.Sprintf("kubectl wait pod --for condition=ready -l name=seccomp-copier -n %s", ns),
		},
		{
			Name: "RunSeccompAuditTestPod",
			Cmd: fmt.Sprintf(`
				kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: ig-test-profile.json
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: test-pod
    image: busybox
    command: ["sh"]
    args: ["-c", "while true; do unshare -i; sleep 1; done"]
EOF
`, ns),
			ExpectedRegexp: "pod/test-pod created",
		},
		WaitUntilTestPodReadyCommand(ns),
		{
			Name: "RunAuditSeccompGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET audit seccomp -n %s --timeout 15 -o json", ns),
			ValidateOutput: func(t *testing.T, output string) {
				expectedEntry := &seccompauditTypes.Event{
					Event:   BuildBaseEvent(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
					Syscall: "unshare",
					Code:    "kill_thread",
					Comm:    "unshare",
				}

				normalize := func(e *seccompauditTypes.Event) {
					e.Timestamp = 0
					e.Pid = 0
					e.MountNsID = 0

					e.K8s.Node = ""
					// TODO: Verify container runtime and container name
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
					e.Runtime.ContainerID = ""
					e.Runtime.ContainerImageDigest = ""
				}

				ExpectEntriesToMatch(t, output, normalize, expectedEntry)
			},
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
