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

func TestTraceloop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-traceloop")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		{
			Name: "StartTraceloopGadget",
			Cmd:  "$KUBECTL_GADGET traceloop start",
		},
		{
			Name: "WaitForTraceloopStarted",
			Cmd:  "sleep 15",
		},
		{
			Name: "RunTraceloopTestPod",
			Cmd:  fmt.Sprintf("kubectl run --restart=Never -n %s --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM ; sleep infinity'", ns),
		},
		{
			Name: "WaitForTraceloopTestPod",
			Cmd:  fmt.Sprintf("sleep 5 ; kubectl wait -n %s --for=condition=ready pod/multiplication ; kubectl get pod -n %s ; sleep 2", ns, ns),
		},
		{
			Name:           "CheckTraceloopList",
			Cmd:            "sleep 20; $KUBECTL_GADGET traceloop list | grep multiplication",
			ExpectedRegexp: "multiplication",
		},
		{
			Name:           "CheckTraceloopShow",
			Cmd:            "CONTAINER_ID=$($KUBECTL_GADGET traceloop list | grep multiplication | awk '{ print $5 }'); $KUBECTL_GADGET traceloop show $CONTAINER_ID | grep -C 5 write",
			ExpectedRegexp: `bc\s+write\s+fd=\d+,\s+buf="42`,
		},
		{
			Name:    "PrintTraceloopList",
			Cmd:     "$KUBECTL_GADGET traceloop list",
			Cleanup: true,
		},
		{
			Name:    "StopTraceloopGadget",
			Cmd:     "$KUBECTL_GADGET traceloop stop",
			Cleanup: true,
		},
		{
			Name:    "WaitForTraceloopStopped",
			Cmd:     "sleep 15",
			Cleanup: true,
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
