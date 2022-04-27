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
	"math/rand"
	"os"
	"testing"
	"time"
)

var (
	integration = flag.Bool("integration", false, "run integration tests")

	// image such as docker.io/kinvolk/gadget:latest
	image = flag.String("image", "", "gadget container image")

	doNotDeployIG  = flag.Bool("no-deploy-ig", false, "don't deploy Inspektor Gadget")
	doNotDeploySPO = flag.Bool("no-deploy-spo", false, "don't deploy the Security Profiles Operator (SPO)")
)

func runCommands(cmds []*command, t *testing.T) {
	// defer all cleanup commands so we are sure to exit clean whatever
	// happened
	defer func() {
		for _, cmd := range cmds {
			if cmd.cleanup {
				cmd.run(t)
			}
		}
	}()

	// defer stopping commands
	defer func() {
		for _, cmd := range cmds {
			if cmd.startAndStop && cmd.started {
				// Wait a bit before stopping the command.
				time.Sleep(10 * time.Second)
				cmd.stop(t)
			}
		}
	}()

	// run all commands but cleanup ones
	for _, cmd := range cmds {
		if cmd.cleanup {
			continue
		}

		cmd.run(t)
	}
}

func testMain(m *testing.M) int {
	flag.Parse()

	if !*integration {
		fmt.Println("Skipping integration test.")
		return 0
	}

	if os.Getenv("KUBECTL_GADGET") == "" {
		fmt.Fprintf(os.Stderr, "please set $KUBECTL_GADGET.")
		return -1
	}

	if *image != "" {
		os.Setenv("GADGET_IMAGE_FLAG", "--image "+*image)
	}

	seed := time.Now().UTC().UnixNano()
	rand.Seed(seed)
	fmt.Printf("using random seed: %d\n", seed)

	initCommands := []*command{}

	if !*doNotDeploySPO {
		initCommands = append(initCommands, deploySPO)
		defer func() {
			fmt.Printf("Clean SPO:\n")
			cleanupSPO.runWithoutTest()
		}()
	}

	if !*doNotDeployIG {
		initCommands = append(initCommands, deployInspektorGadget)
		initCommands = append(initCommands, waitUntilInspektorGadgetPodsDeployed)
		initCommands = append(initCommands, waitUntilInspektorGadgetPodsInitialized)

		// defer the cleanup to be sure it's called if the test
		// fails (hence calling runtime.Goexit())
		defer func() {
			fmt.Printf("Clean inspektor-gadget:\n")
			cleanupInspektorGadget.runWithoutTest()
		}()
	}

	fmt.Printf("Running init commands:\n")
	for _, cmd := range initCommands {
		err := cmd.runWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return -1
		}
	}

	return m.Run()
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func TestAuditSeccomp(t *testing.T) {
	ns := generateTestNamespaceName("test-audit-seccomp")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name: "Create SeccompProfile",
			cmd: fmt.Sprintf(`
				kubectl apply -f - <<EOF
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: log
  namespace: %s
  annotations:
    description: "Log some syscalls"
spec:
  defaultAction: SCMP_ACT_ALLOW
  architectures:
  - SCMP_ARCH_X86_64
  syscalls:
  - action: SCMP_ACT_KILL
    names:
    - unshare
  - action: SCMP_ACT_LOG
    names:
    - mkdir
EOF
			`, ns),
			expectedRegexp: "seccompprofile.security-profiles-operator.x-k8s.io/log created",
		},
		{
			name: "Run test pod",
			cmd: fmt.Sprintf(`
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
  containers:
  - name: container1
    image: busybox
    command: ["sh"]
    args: ["-c", "while true; do unshare -i; sleep 1; done"]
EOF
			`, ns, ns),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run audit-seccomp gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET audit seccomp -n %s & sleep 5; kill $!", ns),
			expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+container1\s+unshare\s+\d+\s+unshare\s+kill_thread`, ns),
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestBindsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-bindsnoop")

	t.Parallel()

	bindsnoopCmd := &command{
		name:           "Start bindsnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace bind -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+nc`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		bindsnoopCmd,
		busyboxPodRepeatCommand(ns, "nc -l -p 9090 -w 1"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestBiolatency(t *testing.T) {
	t.Parallel()

	commands := []*command{
		{
			name:           "Run biolatency gadget",
			cmd:            "id=$($KUBECTL_GADGET profile block-io start --node $(kubectl get node --no-headers | cut -d' ' -f1)); sleep 15; $KUBECTL_GADGET profile block-io stop $id",
			expectedRegexp: `usecs\s+:\s+count\s+distribution`,
		},
	}

	runCommands(commands, t)
}

func TestBiotop(t *testing.T) {
	ns := generateTestNamespaceName("test-biotop")

	t.Parallel()

	biotopCmd := &command{
		name:           "Start biotop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET top block-io -n %s", ns),
		expectedRegexp: `test-pod\s+test-pod\s+\d+\s+dd`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		biotopCmd,
		busyboxPodRepeatCommand(ns, "dd if=/dev/zero of=/tmp/test count=4096"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestCapabilities(t *testing.T) {
	ns := generateTestNamespaceName("test-capabilities")

	t.Parallel()

	capabilitiesCmd := &command{
		name:           "Start capabilities gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace capabilities -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod.*nice.*CAP_SYS_NICE`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		capabilitiesCmd,
		busyboxPodRepeatCommand(ns, "nice -n -20 echo"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestDns(t *testing.T) {
	ns := generateTestNamespaceName("test-dns")

	t.Parallel()

	dnsCmd := &command{
		name:           "Start dns gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace dns -n %s", ns),
		expectedRegexp: `test-pod\s+OUTGOING\s+A\s+microsoft.com`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		dnsCmd,
		busyboxPodRepeatCommand(ns, "nslookup microsoft.com"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestExecsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-execsnoop")

	t.Parallel()

	execsnoopCmd := &command{
		name:           "Start execsnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace exec -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+date`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		execsnoopCmd,
		busyboxPodRepeatCommand(ns, "date"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestFiletop(t *testing.T) {
	ns := generateTestNamespaceName("test-filetop")

	t.Parallel()

	filetopCmd := &command{
		name:           "Start filetop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET top file -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+\S*\s+0\s+\d+\s+0\s+\d+\s+R\s+date`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		filetopCmd,
		busyboxPodRepeatCommand(ns, "echo date >> /tmp/date.txt"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestFsslower(t *testing.T) {
	ns := generateTestNamespaceName("test-fsslower")

	t.Parallel()

	fsslowerCmd := &command{
		name:           "Start fsslower gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace fsslower -n %s -t ext4 -m 0", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+cat`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		fsslowerCmd,
		busyboxPodCommand(ns, "echo 'this is foo' > foo && while true; do cat foo && sleep 0.1; done"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestMountsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-mountsnoop")

	t.Parallel()

	mountsnoopCmd := &command{
		name:           "Start mountsnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace mount -n %s", ns),
		expectedRegexp: `test-pod\s+test-pod\s+mount.*mount\("/mnt", "/mnt", .*\) = -2`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		mountsnoopCmd,
		busyboxPodRepeatCommand(ns, "mount /mnt /mnt"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestNetworkpolicy(t *testing.T) {
	ns := generateTestNamespaceName("test-networkpolicy")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		busyboxPodRepeatCommand(ns, "wget -q -O /dev/null https://kinvolk.io"),
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run network-policy gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET advise network-policy monitor -n %s --output ./networktrace.log & sleep 15; kill $!; head networktrace.log", ns),
			expectedRegexp: fmt.Sprintf(`"type":"connect".*"%s".*"test-pod"`, ns),
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestOomkill(t *testing.T) {
	ns := generateTestNamespaceName("test-oomkill")

	t.Parallel()

	oomkillCmd := &command{
		name:           "Start oomkill gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace oomkill -n %s", ns),
		expectedRegexp: `\d+\s+tail`,
		startAndStop:   true,
	}

	limitPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
spec:
  containers:
  - name: test-pod-container
    image: busybox
    resources:
      limits:
        memory: "128Mi"
    command: ["/bin/sh", "-c"]
    args:
    - while true; do tail /dev/zero; done
`, ns)

	commands := []*command{
		createTestNamespaceCommand(ns),
		oomkillCmd,
		{
			name:           "Run pod which exhaust memory with memory limits",
			cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", limitPodYaml),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestOpensnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-opensnoop")

	t.Parallel()

	opensnoopCmd := &command{
		name:           "Start opensnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace open -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+whoami\s+3`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		opensnoopCmd,
		busyboxPodRepeatCommand(ns, "whoami"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestProcessCollector(t *testing.T) {
	ns := generateTestNamespaceName("test-process-collector")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		busyboxPodCommand(ns, "nc -l -p 9090"),
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run process-collector gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET snapshot process -n %s", ns),
			expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+nc\s+\d+`, ns),
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestProfile(t *testing.T) {
	ns := generateTestNamespaceName("test-profile")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		busyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run profile gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET profile cpu -n %s -p test-pod -K & sleep 15; kill $!", ns),
			expectedRegexp: `sh;\w+;\w+;\w+open`, // echo is builtin.
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSeccompadvisor(t *testing.T) {
	ns := generateTestNamespaceName("test-seccomp-advisor")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		busyboxPodRepeatCommand(ns, "echo foo"),
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run seccomp-advisor gadget",
			cmd:            fmt.Sprintf("id=$($KUBECTL_GADGET advise seccomp-profile start -n %s -p test-pod); sleep 30; $KUBECTL_GADGET advise seccomp-profile stop $id", ns),
			expectedRegexp: `write`,
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSigsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-sigsnoop")

	t.Parallel()

	sigsnoopCmd := &command{
		name:           "Start sigsnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace signal -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+sh\s+SIGTERM`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		sigsnoopCmd,
		busyboxPodRepeatCommand(ns, "sleep 3 & kill $!"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSnisnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-snisnoop")

	t.Parallel()

	snisnoopCmd := &command{
		name:           "Start snisnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace sni -n %s", ns),
		expectedRegexp: `test-pod\s+kinvolk.io`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		snisnoopCmd,
		busyboxPodRepeatCommand(ns, "wget -q -O /dev/null https://kinvolk.io"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSocketCollector(t *testing.T) {
	ns := generateTestNamespaceName("test-socket-collector")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		busyboxPodCommand(ns, "nc -l 0.0.0.0 -p 9090"),
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run socket-collector gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET snapshot socket -n %s", ns),
			expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+TCP\s+0\.0\.0\.0`, ns),
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTcpconnect(t *testing.T) {
	ns := generateTestNamespaceName("test-tcpconnect")

	t.Parallel()

	tcpconnectCmd := &command{
		name:           "Start tcpconnect gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace tcpconnect -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+wget`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		tcpconnectCmd,
		busyboxPodRepeatCommand(ns, "wget -q -O /dev/null -T 3 http://1.1.1.1"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTcptracer(t *testing.T) {
	ns := generateTestNamespaceName("test-tcptracer")

	t.Parallel()

	tcptracerCmd := &command{
		name:           "Start tcptracer gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace tcp -n %s", ns),
		expectedRegexp: `C\s+\d+\s+wget\s+\d\s+[\w\.:]+\s+1\.1\.1\.1\s+\d+\s+80`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		tcptracerCmd,
		busyboxPodRepeatCommand(ns, "wget -q -O /dev/null -T 3 http://1.1.1.1"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTcptop(t *testing.T) {
	ns := generateTestNamespaceName("test-tcptop")

	t.Parallel()

	tcptopCmd := &command{
		name:           "Start tcptop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET top tcp --node $(kubectl get node --no-headers | cut -d' ' -f1) -n %s -p test-pod", ns),
		expectedRegexp: `wget`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		tcptopCmd,
		busyboxPodRepeatCommand(ns, "wget -q -O /dev/null https://kinvolk.io"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTraceloop(t *testing.T) {
	ns := generateTestNamespaceName("test-traceloop")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
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
			cmd:  fmt.Sprintf("kubectl run --restart=Never -n %s --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM ; sleep infinity'", ns),
		},
		{
			name: "Wait until multiplication pod is ready",
			cmd:  fmt.Sprintf("sleep 5 ; kubectl wait -n %s --for=condition=ready pod/multiplication ; kubectl get pod -n %s ; sleep 2", ns, ns),
		},
		{
			name:           "Check traceloop list",
			cmd:            fmt.Sprintf("sleep 20 ; $KUBECTL_GADGET traceloop list -n %s --no-headers | grep multiplication | awk '{print $1\" \"$6}'", ns),
			expectedString: "multiplication started\n",
		},
		{
			name:           "Check traceloop show",
			cmd:            fmt.Sprintf(`TRACE_ID=$($KUBECTL_GADGET traceloop list -n %s --no-headers | `, ns) + `grep multiplication | awk '{printf "%s", $4}') ; $KUBECTL_GADGET traceloop show $TRACE_ID | grep -C 5 write`,
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
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}
