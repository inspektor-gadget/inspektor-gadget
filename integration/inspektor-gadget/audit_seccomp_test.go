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
	spName := "log"

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		{
			Name: "CreateSeccompProfile",
			Cmd: fmt.Sprintf(`
				kubectl apply -f - <<EOF
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
  namespace: %s
  annotations:
    description: "Log some syscalls"
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_KILL
    names:
    - unshare
  - action: SCMP_ACT_LOG
    names:
    - mkdir
EOF
			`, spName, ns),
			ExpectedRegexp: fmt.Sprintf("seccompprofile.security-profiles-operator.x-k8s.io/%s created", spName),
		},
		{
			Name: "WaitForSeccompProfile",
			Cmd:  fmt.Sprintf("kubectl wait sp --for condition=ready -n %s %s", ns, spName),
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
      localhostProfile: operator/%s/log.json
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: test-pod
    image: busybox
    command: ["sh"]
    args: ["-c", "while true; do unshare -i; sleep 1; done"]
EOF
			`, ns, ns),
			ExpectedRegexp: "pod/test-pod created",
		},
		WaitUntilTestPodReadyCommand(ns),
		{
			Name: "RunAuditSeccompGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET audit seccomp -n %s --timeout 15 -o json", ns),
			ExpectedOutputFn: func(output string) error {
				expectedEntry := &seccompauditTypes.Event{
					Event:   BuildBaseEvent(ns),
					Syscall: "unshare",
					Code:    "kill_thread",
					Comm:    "unshare",
				}

				normalize := func(e *seccompauditTypes.Event) {
					e.Node = ""
					e.Pid = 0
					e.MountNsID = 0
				}

				return ExpectEntriesToMatch(output, normalize, expectedEntry)
			},
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
