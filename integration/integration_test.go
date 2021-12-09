// Copyright 2019-2021 The Inspektor Gadget authors
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
)

var integration = flag.Bool("integration", false, "run integration tests")

// image such as docker.io/kinvolk/gadget:latest
var image = flag.String("image", "", "gadget container image")

func runCommands(cmds []*command, t *testing.T) {
	defer func() {
		for _, cmd := range cmds {
			if !cmd.cleanup {
				continue
			}

			// Defer all cleanup commands so we are sure to exit clean whatever
			// happened.
			cmd.run(t)
		}
	}()

	for _, cmd := range cmds {
		if cmd.cleanup {
			continue
		}

		cmd.run(t)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()

	if !*integration {
		fmt.Println("Skipping integration test.")

		os.Exit(0)
	}

	if os.Getenv("KUBECTL_GADGET") == "" {
		fmt.Fprintf(os.Stderr, "please set $KUBECTL_GADGET.")

		os.Exit(-1)
	}

	if *image != "" {
		os.Setenv("GADGET_IMAGE_FLAG", "--image "+*image)
	}

	initCommands := []*command{
		deployInspektorGadget,
		waitUntilInspektorGadgetPodsDeployed,
		waitUntilInspektorGadgetPodsInitialized,
		createTestNamespace,
	}

	fmt.Printf("Setup inspektor-gadget:\n")
	for _, cmd := range initCommands {
		err := cmd.runWithoutTest()

		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)

			os.Exit(-1)
		}
	}

	ret := m.Run()

	fmt.Printf("Clean inspektor-gadget:\n")
	cleanupTestNamespace.runWithoutTest()
	cleanupInspektorGadget.runWithoutTest()

	os.Exit(ret)
}

func TestTraceloop(t *testing.T) {
	commands := []*command{
		{
			name: "Start the traceloop gadget",
			cmd:  "$KUBECTL_GADGET traceloop start",
		},
		{
			name: "Wait traceloop to be started",
			cmd:  "sleep 15",
		},
		{
			name: "Run multiplication pod",
			cmd:  "kubectl run --restart=Never -n test-ns --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM ; sleep infinity'",
		},
		{
			name: "Wait until multiplication pod is ready",
			cmd:  "sleep 5 ; kubectl wait -n test-ns --for=condition=ready pod/multiplication ; kubectl get pod -n test-ns ; sleep 2",
		},
		{
			name:           "Check traceloop list",
			cmd:            "sleep 20 ; $KUBECTL_GADGET traceloop list -n test-ns --no-headers | grep multiplication | awk '{print $1\" \"$6}'",
			expectedString: "multiplication started\n",
		},
		{
			name: "Check traceloop show",
			cmd: `TRACE_ID=$($KUBECTL_GADGET traceloop list -n test-ns --no-headers | grep multiplication | awk '{printf "%s", $4}') ; ` +
				`$KUBECTL_GADGET traceloop show $TRACE_ID | grep -C 5 write`,
			expectedRegexp: "\\[bc\\] write\\(1, \"42\\\\n\", 3\\)",
		},
		{
			name:    "traceloop list",
			cmd:     "$KUBECTL_GADGET traceloop list -A",
			cleanup: true,
		},
		{
			name:           "Stop the traceloop gadget",
			cmd:            "$KUBECTL_GADGET traceloop stop",
			expectedString: "",
			cleanup:        true,
		},
		{
			name:    "Wait until traceloop is stopped",
			cmd:     "sleep 15",
			cleanup: true,
		},
	}

	runCommands(commands, t)
}
