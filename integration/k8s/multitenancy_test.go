// Copyright 2026 The Inspektor Gadget authors
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
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestMultiTenancyTokenReviewNamespacePolicy(t *testing.T) {
	if DefaultTestComponent != InspektorGadgetTestComponent {
		t.Skip("multi-tenancy TokenReview policy is enforced by the deployed Inspektor Gadget daemon")
	}

	kubectlGadget := os.Getenv("KUBECTL_GADGET")
	require.NotEmpty(t, kubectlGadget, "KUBECTL_GADGET is not set")

	teamA := GenerateTestNamespaceName("mt-team-a")
	teamB := GenerateTestNamespaceName("mt-team-b")
	instanceName := GenerateTestNamespaceName("mt-snapshot")
	gadgetImage := fmt.Sprintf("%s/snapshot_process:%s", *gadgetRepository, *gadgetTag)

	cleanupCommands := []TestStep{
		&Command{
			Name:    "Delete detached gadget instance",
			Cmd:     fmt.Sprintf("%s --auth-service-account=%s/ig-client delete %s || true", q(kubectlGadget), teamA, q(instanceName)),
			Cleanup: true,
		},
		&Command{
			Name: "Restore non-multi-tenant Inspektor Gadget",
			Cmd: fmt.Sprintf(`ig_image="$(kubectl -n gadget get daemonset gadget -o jsonpath='{.spec.template.spec.containers[0].image}')"
%[1]s undeploy || true
%[1]s deploy --experimental --debug \
  --image="$ig_image" \
  --image-pull-policy=IfNotPresent \
  --set-daemon-config=operator.oci.verify-image=false`,
				q(kubectlGadget),
			),
			Cleanup: true,
		},
		&Command{
			Name:    "Delete auth delegator binding",
			Cmd:     "kubectl delete clusterrolebinding gadget-multitenancy-test-auth-delegator --ignore-not-found",
			Cleanup: true,
		},
		DeleteTestNamespaceCommand(teamA),
		DeleteTestNamespaceCommand(teamB),
	}
	t.Cleanup(func() {
		RunTestSteps(cleanupCommands, t)
	})

	commands := []TestStep{
		&Command{
			Name: "Deploy Inspektor Gadget with TokenReview",
			Cmd: fmt.Sprintf(`ig_image="$(kubectl -n gadget get daemonset gadget -o jsonpath='{.spec.template.spec.containers[0].image}')"
%[1]s undeploy || true
%[1]s deploy --experimental --debug \
  --image="$ig_image" \
  --image-pull-policy=IfNotPresent \
  --set-daemon-config=operator.oci.verify-image=false \
  --set-daemon-config=multi-tenancy=true
kubectl create clusterrolebinding gadget-multitenancy-test-auth-delegator \
  --clusterrole=system:auth-delegator \
  --serviceaccount=gadget:gadget \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout status daemonset/gadget -n gadget --timeout=120s`,
				q(kubectlGadget),
			),
		},
		CreateTestNamespaceCommand(teamA),
		CreateTestNamespaceCommand(teamB),
		multiTenancyRBACCommand(teamA),
		multiTenancyRBACCommand(teamB),
		&Command{
			Name: "Team A can run in team A namespace",
			Cmd: fmt.Sprintf("%s --auth-service-account=%s/ig-client run %s -n %s --timeout=5 -o json",
				q(kubectlGadget), teamA, q(gadgetImage), q(teamA)),
		},
		&Command{
			Name: "Team A cannot run in team B namespace",
			Cmd: fmt.Sprintf(`if %s --auth-service-account=%s/ig-client run %s -n %s --timeout=5; then
  echo "team A unexpectedly ran a gadget in team B namespace"
  exit 1
fi`,
				q(kubectlGadget), teamA, q(gadgetImage), q(teamB)),
		},
		&Command{
			Name: "Team A all-namespaces request is narrowed to team A",
			Cmd: fmt.Sprintf("%s --auth-service-account=%s/ig-client run %s -A --timeout=5 -o json",
				q(kubectlGadget), teamA, q(gadgetImage)),
		},
		&Command{
			Name: "Team A can install a detached gadget in team A namespace",
			Cmd: fmt.Sprintf("%s --auth-service-account=%s/ig-client run %s --detach --name %s -n %s",
				q(kubectlGadget), teamA, q(gadgetImage), q(instanceName), q(teamA)),
		},
		&Command{
			Name: "Team B cannot list team A detached gadget",
			Cmd: fmt.Sprintf(`if %s --auth-service-account=%s/ig-client list | grep -F %s; then
  echo "team B unexpectedly listed team A detached gadget"
  exit 1
fi`,
				q(kubectlGadget), teamB, q(instanceName)),
		},
		&Command{
			Name: "Team B cannot delete team A detached gadget",
			Cmd: fmt.Sprintf(`instance_id=$(%[1]s --auth-service-account=%[2]s/ig-client show %[3]s | awk '$1 == "ID:" {print $2}')
if [ -z "$instance_id" ]; then
  echo "failed to resolve team A gadget instance ID"
  exit 1
fi
set +e
delete_output=$(%[1]s --auth-service-account=%[4]s/ig-client delete "$instance_id" 2>&1)
rc=$?
if [ "$rc" -eq 0 ]; then
  echo "team B unexpectedly deleted team A detached gadget"
  exit 1
fi
if ! printf '%%s\n' "$delete_output" | grep -F "code = PermissionDenied"; then
  echo "delete failed without PermissionDenied: $delete_output"
  exit 1
fi
%[1]s --auth-service-account=%[2]s/ig-client show "$instance_id" >/dev/null`,
				q(kubectlGadget), teamA, q(instanceName), teamB),
		},
		&Command{
			Name: "Team A can attach to its detached gadget",
			Cmd: fmt.Sprintf(`set +e
timeout 10s %s --auth-service-account=%s/ig-client attach %s
rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
  exit "$rc"
fi`,
				q(kubectlGadget), teamA, q(instanceName)),
		},
		&Command{
			Name: "Team B cannot attach to team A detached gadget",
			Cmd: fmt.Sprintf(`set +e
timeout 10s %s --auth-service-account=%s/ig-client attach %s
rc=$?
if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then
  echo "team B unexpectedly attached to team A detached gadget"
  exit 1
fi`,
				q(kubectlGadget), teamB, q(instanceName)),
		},
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn("gadget", teamA, teamB)))
}

func multiTenancyRBACCommand(namespace string) *Command {
	cmd := fmt.Sprintf(`kubectl apply -f - <<"EOF"
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ig-client
  namespace: %[1]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-creator
  namespace: %[1]s
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ig-client-pod-creator
  namespace: %[1]s
subjects:
- kind: ServiceAccount
  name: ig-client
  namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-creator
EOF`, namespace)

	return &Command{
		Name: fmt.Sprintf("Create team RBAC in %s", namespace),
		Cmd:  cmd,
	}
}

func q(s string) string {
	return strconv.Quote(s)
}
