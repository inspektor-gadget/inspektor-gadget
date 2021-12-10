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
	"time"
)

var integration = flag.Bool("integration", false, "run integration tests")

// image such as docker.io/kinvolk/gadget:latest
var image = flag.String("image", "", "gadget container image")

func runCommands(cmds []*command, t *testing.T) {
	defer func() {
		for _, cmd := range cmds {
			if cmd.startAndStop && cmd.started {
				// Wait a bit before stopping the command.
				time.Sleep(10 * time.Second)

				cmd.stop(t)

				continue
			}

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

func TestCapabilities(t *testing.T) {
	capabilitiesCmd := &command{
		name:           "Start capabilities gadget",
		cmd:            "$KUBECTL_GADGET capabilities -n test-ns",
		expectedRegexp: `test-ns\s+test-pod.*nice.*CAP_SYS_NICE`,
		startAndStop:   true,
	}

	commands := []*command{
		capabilitiesCmd,
		{
			name:           "Run pod which fails to run nice",
			cmd:            busyboxPodCommand("while true; do nice -n -20 echo; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReady,
		deleteTestPod,
	}

	runCommands(commands, t)
}

func TestDns(t *testing.T) {
	dnsCmd := &command{
		name:           "Start dns gadget",
		cmd:            "$KUBECTL_GADGET dns -n test-ns",
		expectedRegexp: `test-pod\s+OUTGOING\s+microsoft.com`,
		startAndStop:   true,
	}

	commands := []*command{
		dnsCmd,
		{
			name:           "Run pod which interacts with dns",
			cmd:            "kubectl run --restart=Never --image=praqma/network-multitool -n test-ns test-pod -- sh -c 'while true; do nslookup microsoft.com; done'",
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReady,
		deleteTestPod,
	}

	runCommands(commands, t)
}

func TestExecsnoop(t *testing.T) {
	execsnoopCmd := &command{
		name:           "Start execsnoop gadget",
		cmd:            "$KUBECTL_GADGET execsnoop -n test-ns",
		expectedRegexp: `test-ns\s+test-pod\s+test-pod\s+date`,
		startAndStop:   true,
	}

	commands := []*command{
		execsnoopCmd,
		{
			name:           "Run pod which does a lot of exec",
			cmd:            busyboxPodCommand("while true; do date; done"),
			expectedString: "pod/test-pod created\n",
		},
		waitUntilTestPodReady,
		deleteTestPod,
	}

	runCommands(commands, t)
}

func TestMountsnoop(t *testing.T) {
	mountsnoopCmd := &command{
		name:           "Start mountsnoop gadget",
		cmd:            "$KUBECTL_GADGET mountsnoop -n test-ns",
		expectedRegexp: `test-pod\s+test-pod\s+mount.*mount\("/mnt", "/mnt", .*\) = -ENOENT`,
		startAndStop:   true,
	}

	commands := []*command{
		mountsnoopCmd,
		{
			name:           "Run pod which tries to mount a directory",
			cmd:            busyboxPodCommand("while true; do mount /mnt /mnt; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReady,
		deleteTestPod,
	}

	runCommands(commands, t)
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
