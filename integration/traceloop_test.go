package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"text/template"

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
		outputName     string
		expected       string
		expectedRegexp string
		ignoreOutput   bool
		debugFailed    bool
	}{
		{
			name:         "Cleanup test namespace from previous tests",
			cmd:          "kubectl delete ns test-ig --force --grace-period=0 || true",
			ignoreOutput: true,
		},
		{
			name:         "Cleanup gadget deployment from previous tests",
			cmd:          "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl delete --force --grace-period=0 -f - || true",
			ignoreOutput: true,
		},
		{
			name:     "Deploy Inspektor Gadget",
			cmd:      "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl apply -f -",
			expected: "serviceaccount/gadget created\nclusterrolebinding.rbac.authorization.k8s.io/gadget created\ndaemonset.apps/gadget created\n",
		},
		{
			name:         "Wait until Inspektor Gadget is ready",
			cmd:          "for POD in $(sleep 5 ; kubectl get pod -n kube-system -l k8s-app=gadget -o name) ; do kubectl wait -n kube-system --for=condition=ready $POD ; done ; kubectl get pod -n kube-system ; sleep 15",
			ignoreOutput: true,
		},
		{
			name:     "Create test namespace",
			cmd:      "kubectl create ns test-ig",
			expected: "namespace/test-ig created\n",
		},
		{
			name:         "Run multiplication pod",
			cmd:          "kubectl run --restart=Never -n test-ig --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM ; sleep infinity'",
			ignoreOutput: true,
		},
		{
			name:         "Wait until multiplication pod is ready",
			cmd:          "sleep 5 ; kubectl wait -n test-ig --for=condition=ready pod/multiplication ; kubectl get pod -n test-ig ; sleep 2",
			ignoreOutput: true,
		},
		{
			name:     "Check traceloop list",
			cmd:      "sleep 5 ; $KUBECTL_GADGET traceloop list -n test-ig --no-headers | grep multiplication | awk '{print $1\" \"$6}'",
			expected: "multiplication started\n",
		},
		{
			name:         "Get trace ID for the multiplication pod",
			cmd:          `$KUBECTL_GADGET traceloop list -n test-ig --no-headers | grep multiplication | awk '{printf "%s", $4}'`,
			outputName:   "multiplication_trace_id",
			ignoreOutput: true,
		},
		{
			name:           "Check traceloop show",
			cmd:            `$KUBECTL_GADGET traceloop show {{index .Value "multiplication_trace_id"}}`,
			expectedRegexp: "\\[bc\\] write\\(1, \"42\\\\n\", 3\\) = 3\n",
		},
		{
			name:         "traceloop list",
			cmd:          "$KUBECTL_GADGET traceloop list -A",
			ignoreOutput: true,
			debugFailed:  true,
		},
		{
			name:     "Cleanup test namespace",
			cmd:      "kubectl delete ns test-ig",
			expected: "namespace \"test-ig\" deleted\n",
		},
		{
			name:     "Cleanup gadget deployment",
			cmd:      "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl delete -f -",
			expected: "serviceaccount \"gadget\" deleted\nclusterrolebinding.rbac.authorization.k8s.io \"gadget\" deleted\ndaemonset.apps \"gadget\" deleted\n",
		},
	}

	if os.Getenv("KUBECTL_GADGET") == "" {
		t.Fatalf("please set $KUBECTL_GADGET.")
	}

	if *image != "" {
		os.Setenv("GADGET_IMAGE_FLAG", "--image "+*image)
	}

	type Outputs struct {
		Value map[string]string
	}
	outputs := Outputs{Value: make(map[string]string)}

	failed := false
	for _, tt := range commands {
		t.Run(tt.name, func(t *testing.T) {
			if failed && !tt.debugFailed {
				t.Skip("Previous command failed.")
			}
			tmpl, err := template.New("cmd").Parse(tt.cmd)
			if err != nil {
				failed = true
				t.Fatalf("err: %v", err)
			}

			var tpl bytes.Buffer
			if err := tmpl.Execute(&tpl, outputs); err != nil {
				failed = true
				t.Fatalf("err: %v", err)
			}

			t.Logf("Command: %s\n", tpl.String())
			cmd := exec.Command("/bin/sh", "-c", tpl.String())
			output, err := cmd.CombinedOutput()
			actual := string(output)
			t.Logf("Command returned:\n%s\n", actual)
			if err != nil {
				failed = true
				t.Fatal(err)
			}
			if tt.outputName != "" {
				outputs.Value[tt.outputName] = actual
			}

			if !tt.ignoreOutput {
				if tt.expectedRegexp != "" {
					r := regexp.MustCompile(tt.expectedRegexp)
					if !r.MatchString(actual) {
						failed = true
						t.Fatalf("regexp didn't match: %s\n%s\n", tt.expectedRegexp, actual)
					}
				} else if actual != tt.expected {
					failed = true
					t.Fatalf("diff: %v", pretty.Diff(tt.expected, actual))
				}
			}
		})
	}
}
