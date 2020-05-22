package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"testing"
	"text/template"

	"github.com/kr/pretty"
)

var integration = flag.Bool("integration", false, "run integration tests")

// image such as docker.io/kinvolk/gadget:latest
var image = flag.String("image", "", "gadget container image")

func TestDeploy(t *testing.T) {
	if !*integration {
		t.Skip("skipping integration test.")
	}

	commands := []struct {
		name         string
		cmd          string
		outputName   string
		expected     string
		ignoreOutput bool
	}{
		{
			name:         "Cleanup test namespace from previous tests",
			cmd:          "kubectl delete ns test-ig --force --grace-period=0 || true",
			ignoreOutput: true,
		},
		{
			name:         "Cleanup gadget deployment from previous tests",
			cmd:          "kubectl gadget deploy $GADGET_IMAGE_FLAG | kubectl delete --force --grace-period=0 -f - || true",
			ignoreOutput: true,
		},
		{
			name:     "Deploy Inspektor Gadget",
			cmd:      "$KUBECTL_GADGET deploy $GADGET_IMAGE_FLAG | kubectl apply -f -",
			expected: "serviceaccount/gadget created\nclusterrolebinding.rbac.authorization.k8s.io/gadget created\ndaemonset.apps/gadget created\n",
		},
		{
			name:         "Wait until Inspektor Gadget is ready",
			cmd:          "for POD in $(kubectl get pod -n kube-system -l k8s-app=gadget -o name) ; do kubectl wait -n kube-system --for=condition=ready $POD ; done ; sleep 2",
			ignoreOutput: true,
		},
		{
			name:     "Create test namespace",
			cmd:      "kubectl create ns test-ig",
			expected: "namespace/test-ig created\n",
		},
		{
			name:     "Run multiplication pod",
			cmd:      "kubectl run --restart=Never -ti -n test-ig --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM'",
			expected: "",
		},
		{
			name:     "Check traceloop list",
			cmd:      "sleep 2 ; $KUBECTL_GADGET traceloop list -n test-ig --no-headers | awk '{print $1\" \"$6}'",
			expected: "multiplication deleted\n",
		},
		{
			name:         "Get trace ID for the multiplication pod",
			cmd:          `$KUBECTL_GADGET traceloop list -n test-ig --no-headers | awk '{printf "%s", $4}'`,
			outputName:   "multiplication_trace_id",
			ignoreOutput: true,
		},
		{
			name:     "Check traceloop show",
			cmd:      `$KUBECTL_GADGET traceloop show {{index .Value "multiplication_trace_id"}} | grep '\[bc\] write(1, .*, 3) = 3' | sed 's/^.*\[bc\]/[bc]/'`,
			expected: "[bc] write(1, \"42\\n\", 3) = 3\n",
		},
		{
			name:     "Cleanup test namespace",
			cmd:      "kubectl delete ns test-ig",
			expected: "namespace \"test-ig\" deleted\n",
		},
		{
			name:     "Cleanup gadget deployment",
			cmd:      "kubectl gadget deploy $GADGET_IMAGE_FLAG | kubectl delete -f -",
			expected: "serviceaccount \"gadget\" deleted\nclusterrolebinding.rbac.authorization.k8s.io \"gadget\" deleted\ndaemonset.apps \"gadget\" deleted\n",
		},
	}

	os.Setenv("KUBECTL_GADGET", "../kubectl-gadget")
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
			if failed {
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

			if !tt.ignoreOutput && actual != tt.expected {
				failed = true
				t.Fatalf("diff: %v", pretty.Diff(tt.expected, actual))
			}
		})
	}
}
