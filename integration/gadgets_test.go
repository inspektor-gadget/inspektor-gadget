package main

import (
	"bytes"
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

type command struct {
	id             string
	name           string
	cmd            string
	background     bool
	expectedString string
	expectedRegexp string
	cleanup        bool
}

type backgroundCommand struct {
	id     string
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func TestGadgets(t *testing.T) {
	if !*integration {
		t.Skip("skipping integration test.")
	}

	commands := []command{
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
			id:         "execsnoop",
			name:       "Start execsnoop",
			cmd:        "$KUBECTL_GADGET execsnoop --namespace test-snoop",
			background: true,
		},
		{
			id:         "opensnoop",
			name:       "Start opensnoop",
			cmd:        "$KUBECTL_GADGET opensnoop --namespace test-snoop",
			background: true,
		},
		{
			id:         "tcptracer",
			name:       "Start tcptracer",
			cmd:        "$KUBECTL_GADGET tcptracer --namespace test-snoop",
			background: true,
		},
		{
			name: "Wait until gadgets are ready",
			cmd:  "sleep 10",
		},
		{
			name:           "Create test namespace",
			cmd:            "kubectl create ns test-snoop",
			expectedString: "namespace/test-snoop created\n",
		},
		{
			name: "Run test pod",
			cmd:  "kubectl run -i --restart=Never -n test-snoop --image=busybox snooptest -- sh -c 'sleep 10 ; cat /non-existent ; nc -w 1 -l -p 8080 & (echo ok | nc -w 1 127.0.0.1 8080) ; sleep 10 ; exit 0'",
		},
		{
			id:   "execsnoop",
			name: "Stop execsnoop",
			expectedRegexp: "(?s)NODE PCOMM            PID    PPID   RET ARGS\n" +
				".*/bin/cat /non-existent\n",
		},
		{
			id:   "opensnoop",
			name: "Stop opensnoop",
			expectedRegexp: "(?s)NODE.*PID.*COMM.*FD.*ERR.*PATH\n" +
				".*cat.*/non-existent\n",
		},
		{
			id:             "tcptracer",
			name:           "Stop tcptracer",
			expectedRegexp: "C .*nc .*4 .*127.0.0.1 .*127.0.0.1 .*8080",
		},
		{
			name:           "Cleanup test namespace",
			cmd:            "kubectl delete ns test-snoop",
			expectedString: "namespace \"test-snoop\" deleted\n",
			cleanup:        true,
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

	backgroundCommands := map[string]*backgroundCommand{}

	failed := false
	for _, tt := range commands {
		t.Run(tt.name, func(t *testing.T) {
			if failed && !tt.cleanup {
				t.Skip("Previous command failed.")
			}

			t.Logf("Command %s: %s\n", tt.id, tt.cmd)
			var cmd *exec.Cmd
			var actual string
			if tt.cmd != "" {
				cmd = exec.Command("/bin/sh", "-c", tt.cmd)
			} else {
				bg, ok := backgroundCommands[tt.id]
				if !ok {
					failed = true
					t.Fatalf("cannot find command: %s\n", tt.id)
				}
				cmd = bg.cmd
				actual = bg.stderr.String() + bg.stdout.String()
				t.Logf("Background command returned:\n%s\n", actual)
			}
			if tt.background {
				bg := backgroundCommand{
					cmd: cmd,
				}
				backgroundCommands[tt.id] = &bg
				cmd.Stdout = &bg.stdout
				cmd.Stderr = &bg.stderr
				t.Logf("Start command\n")
				cmd.Start()
			} else if tt.cmd != "" {
				output, err := cmd.CombinedOutput()
				if err != nil {
					failed = true
					t.Fatal(err)
				}
				actual = string(output)
				t.Logf("Command returned:\n%s\n", actual)
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
	for id, bg := range backgroundCommands {
		err := bg.cmd.Process.Kill()
		if err != nil {
			t.Fatalf("cannot kill %s: %s", id, err)
		}
		err = bg.cmd.Wait()
		if err != nil {
			_, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("cannot terminate %s: %s", id, err)
			}
		}
	}
}
