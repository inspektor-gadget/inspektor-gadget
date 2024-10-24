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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestAuditSeccomp(t *testing.T) {
	if DefaultTestComponent != InspektorGadgetTestComponent {
		t.Skip("Skip running test with test component different than kubectl-gadget")
	}

	ns := GenerateTestNamespaceName("test-audit-seccomp")
	t.Parallel()

	seccompInstallerYaml := fmt.Sprintf(`
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
apiVersion: v1
kind: ServiceAccount
metadata:
  name: installer-sa
  namespace: %[1]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: installer-cluster-role-%[1]s
rules:
  - apiGroups: ["security.openshift.io"]
    # It is necessary to use the 'privileged' security context constraints to be
    # able mount host directories as volumes, use the host networking, among others.
    # This will be used only when running on OpenShift:
    # https://docs.openshift.com/container-platform/4.14/authentication/managing-security-context-constraints.html#default-sccs_configuring-internal-oauth
    resources: ["securitycontextconstraints"]
    resourceNames: ["privileged"]
    verbs: ["use"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: installer-cluster-role-binding-%[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: installer-cluster-role-%[1]s
subjects:
  - kind: ServiceAccount
    name: installer-sa
    namespace: %[1]s
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: seccomp-installer
  namespace: %[1]s
spec:
  selector:
    matchLabels:
      name: seccomp-installer
  template:
    metadata:
      labels:
        name: seccomp-installer
    spec:
      serviceAccount: installer-sa
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
        effect: NoSchedule
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: NoSchedule
      containers:
      - name: installer
        image: busybox:latest
        securityContext:
          # needed to mount host volumes
          seLinuxOptions:
              type: "spc_t"
        command: [ "sh", "-c", "cp /sourceprofile/ig-test-profile.json /seccomp/ig-test-profile.json ; sleep inf"]
        lifecycle:
          preStop:
            exec:
              command: ["/bin/sh", "-c", "rm -f /seccomp/ig-test-profile.json"]
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
`, ns)

	commands := []TestStep{
		CreateTestNamespaceCommand(ns),
		&Command{
			Name:           "CreateSeccompProfile",
			Cmd:            fmt.Sprintf("kubectl apply -f - <<EOF%sEOF", seccompInstallerYaml),
			ExpectedRegexp: "daemonset.apps/seccomp-installer created",
		},
		&Command{
			Name: "WaitForDaemonSet",
			Cmd:  fmt.Sprintf("kubectl rollout -n %s status daemonset/seccomp-installer --timeout=120s", ns),
		},
		&Command{
			Name: "RunSeccompAuditTestPod",
			Cmd: fmt.Sprintf(`
				kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
  labels:
    run: test-pod
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
		&Command{
			Name: "RunAuditSeccompGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET audit seccomp -n %s --timeout 15 -o json", ns),
			ValidateOutput: func(t *testing.T, output string) {
				expectedEntry := &seccompauditTypes.Event{
					Event:   BuildBaseEventK8s(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
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
					e.Runtime.ContainerPID = 0
					e.Runtime.ContainerImageDigest = ""
					e.Runtime.ContainerStartedAt = 0
				}

				match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
			},
		},
		&Command{
			Name:    "RemoveSeccompProfile",
			Cmd:     fmt.Sprintf("kubectl delete -f - <<EOF%sEOF", seccompInstallerYaml),
			Cleanup: true,
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
