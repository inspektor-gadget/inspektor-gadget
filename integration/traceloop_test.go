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
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/kr/pretty"
)

var integration = flag.Bool("integration", false, "run integration tests")

// image such as docker.io/kinvolk/gadget:latest
var image = flag.String("image", "", "gadget container image")

func TestTraceloop(t *testing.T) {
	if !*integration {
		t.Skip("skipping integration test.")
	}

	commands := []struct {
		name           string
		cmd            string
		expectedString string
		expectedRegexp string
		cleanup        bool
	}{
		{
			name:           "Deploy Inspektor Gadget",
			cmd:            "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl apply -f -",
			expectedRegexp: "gadget created",
		},
		{
			name: "Wait until the gadget pods are started",
			cmd:  "for POD in $(sleep 5 ; kubectl get pod -n kube-system -l k8s-app=gadget -o name) ; do kubectl wait --timeout=30s -n kube-system --for=condition=ready $POD ; done ; kubectl get pod -n kube-system",
		},
		{
			name: "Wait until Inspektor Gadget is initialised",
			cmd:  "sleep 15",
		},
		{
			name:           "Create test namespace",
			cmd:            "kubectl create ns test-traceloop",
			expectedString: "namespace/test-traceloop created\n",
		},
		{
			name: "Run multiplication pod",
			cmd:  "kubectl run --restart=Never -n test-traceloop --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM ; sleep infinity'",
		},
		{
			name: "Wait until multiplication pod is ready",
			cmd:  "sleep 5 ; kubectl wait -n test-traceloop --for=condition=ready pod/multiplication ; kubectl get pod -n test-traceloop ; sleep 2",
		},
		{
			name:           "Check traceloop list",
			cmd:            "sleep 5 ; $KUBECTL_GADGET traceloop list -n test-traceloop --no-headers | grep multiplication | awk '{print $1\" \"$6}'",
			expectedString: "multiplication started\n",
		},
		{
			name: "Check traceloop show",
			cmd: `TRACE_ID=$($KUBECTL_GADGET traceloop list -n test-traceloop --no-headers | grep multiplication | awk '{printf "%s", $4}') ; ` +
				`$KUBECTL_GADGET traceloop show $TRACE_ID | grep -C 5 write`,
			expectedRegexp: "\\[bc\\] write\\(1, \"42\\\\n\", 3\\)",
		},
		{
			name:    "traceloop list",
			cmd:     "$KUBECTL_GADGET traceloop list -A",
			cleanup: true,
		},
		{
			name:           "Cleanup test namespace",
			cmd:            "kubectl delete ns test-traceloop",
			expectedString: "namespace \"test-traceloop\" deleted\n",
			cleanup:        true,
		},
		{
			name:           "Cleanup gadget deployment",
			cmd:            "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl delete -f -",
			expectedRegexp: "\"gadget\" deleted",
			cleanup:        true,
		},
	}

	if os.Getenv("KUBECTL_GADGET") == "" {
		t.Fatalf("please set $KUBECTL_GADGET.")
	}

	if *image != "" {
		os.Setenv("GADGET_IMAGE_FLAG", "--image "+*image)
	}

	failed := false
	for _, tt := range commands {
		t.Run(tt.name, func(t *testing.T) {
			if failed && !tt.cleanup {
				t.Skip("Previous command failed.")
			}

			t.Logf("Command: %s\n", tt.cmd)
			cmd := exec.Command("/bin/sh", "-c", tt.cmd)
			output, err := cmd.CombinedOutput()
			actual := string(output)
			t.Logf("Command returned:\n%s\n", actual)
			if err != nil {
				failed = true
				t.Fatal(err)
			}

			if tt.expectedRegexp != "" {
				r := regexp.MustCompile(tt.expectedRegexp)
				if !r.MatchString(actual) {
					failed = true
					t.Fatalf("regexp didn't match: %s\n%s\n", tt.expectedRegexp, actual)
				}
			}
			if tt.expectedString != "" && actual != tt.expectedString {
				failed = true
				t.Fatalf("diff: %v", pretty.Diff(tt.expectedString, actual))
			}
		})
	}
}
