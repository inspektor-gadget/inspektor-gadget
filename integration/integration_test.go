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
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	bindTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/bind/types"
	execTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/exec/types"
	openTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/open/types"
	signalTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/signal/types"
	tcpTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/tcp/types"
)

const (
	K8sDistroAKSUbuntu  = "aks-Ubuntu"
	K8sDistroARO        = "aro"
	K8sDistroMinikubeGH = "minikube-github"
)

var (
	supportedK8sDistros = []string{K8sDistroAKSUbuntu, K8sDistroARO, K8sDistroMinikubeGH}
	cleaningUp          = uint32(0)
)

var (
	integration = flag.Bool("integration", false, "run integration tests")

	// image such as ghcr.io/kinvolk/inspektor-gadget:latest
	image = flag.String("image", "", "gadget container image")

	doNotDeployIG  = flag.Bool("no-deploy-ig", false, "don't deploy Inspektor Gadget")
	doNotDeploySPO = flag.Bool("no-deploy-spo", false, "don't deploy the Security Profiles Operator (SPO)")

	k8sDistro = flag.String("k8s-distro", "", "allows to skip tests that are not supported on a given Kubernetes distribution")
	k8sArch   = flag.String("k8s-arch", "amd64", "allows to skip tests that are not supported on a given CPU architecture")
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

func cleanupFunc(cleanupCommands []*command) {
	if !atomic.CompareAndSwapUint32(&cleaningUp, 0, 1) {
		return
	}

	fmt.Println("Cleaning up...")

	// We don't want to wait for each cleanup command to finish before
	// running the next one because in the case the workflow run is
	// cancelled, we have few seconds (7.5s + 2.5s) before the runner kills
	// the entire process tree. Therefore, let's try to, at least, launch
	// the cleanup process in the cluster:
	// https://docs.github.com/en/actions/managing-workflow-runs/canceling-a-workflow#steps-github-takes-to-cancel-a-workflow-run
	for _, cmd := range cleanupCommands {
		err := cmd.startWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
	}

	for _, cmd := range cleanupCommands {
		err := cmd.waitWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
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

	if *k8sDistro != "" {
		found := false
		for _, val := range supportedK8sDistros {
			if *k8sDistro == val {
				found = true
				break
			}
		}

		if !found {
			fmt.Fprintf(os.Stderr, "Error: invalid argument '-k8s-distro': %q. Valid values: %s\n",
				*k8sDistro, strings.Join(supportedK8sDistros, ", "))
			return -1
		}
	}

	seed := time.Now().UTC().UnixNano()
	rand.Seed(seed)
	fmt.Printf("using random seed: %d\n", seed)

	initCommands := []*command{}
	cleanupCommands := []*command{deleteRemainingNamespacesCommand()}

	if !*doNotDeployIG {
		imagePullPolicy := "Always"
		livenessProbe := true
		// livenessProbe are causing some issues in the ARO integration cluster,
		// see: https://github.com/kinvolk/inspektor-gadget/issues/799
		if *k8sDistro == K8sDistroARO {
			livenessProbe = false
		}
		if *k8sDistro == K8sDistroMinikubeGH {
			imagePullPolicy = "Never"
		}
		deployCmd := deployInspektorGadget(*image, imagePullPolicy, livenessProbe)
		initCommands = append(initCommands, deployCmd)

		cleanupCommands = append(cleanupCommands, cleanupInspektorGadget)
	}

	if !*doNotDeploySPO {
		limitReplicas := false
		bestEffortResourceMgmt := false
		if *k8sDistro == K8sDistroMinikubeGH {
			limitReplicas = true
			bestEffortResourceMgmt = true
		}

		initCommands = append(initCommands, deploySPO(limitReplicas, bestEffortResourceMgmt))
		cleanupCommands = append(cleanupCommands, cleanupSPO)
	}

	notifyInitDone := make(chan bool, 1)

	cancel := make(chan os.Signal, 1)
	signal.Notify(cancel, syscall.SIGINT)

	cancelling := false
	notifyCancelDone := make(chan bool, 1)

	go func() {
		for {
			<-cancel
			fmt.Printf("\nHandling cancellation...\n")

			if cancelling {
				fmt.Println("Warn: Forcing cancellation. Resources couldn't have been cleaned up")
				os.Exit(1)
			}
			cancelling = true

			go func() {
				defer func() {
					// This will actually never be called due to the os.Exit()
					// but the notifyCancelDone channel helps to make the main
					// go routing wait for the handler to finish the clean up.
					notifyCancelDone <- true
				}()

				// Start by stopping the init commands (in the case they are
				// still running) to avoid trying to undeploy resources that are
				// being deployed.
				fmt.Println("Stop init commands (if they are still running)...")
				for _, cmd := range initCommands {
					err := cmd.killWithoutTest()
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s\n", err)
					}
				}

				// Wait until init commands have exited before starting the
				// cleanup.
				<-notifyInitDone

				cleanupFunc(cleanupCommands)
				os.Exit(1)
			}()
		}
	}()

	fmt.Printf("Running init commands:\n")

	initDone := true
	for _, cmd := range initCommands {
		if cancelling {
			initDone = false
			break
		}

		err := cmd.runWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			initDone = false
			break
		}
	}

	// Notify the cancelling handler that the init commands finished
	notifyInitDone <- initDone

	defer cleanupFunc(cleanupCommands)

	if !initDone {
		// If needed, wait for the cancelling handler to finish before exiting
		// from the main go routine. Otherwise, the cancelling handler will be
		// terminated as well and the cleanup operations will not be completed.
		if cancelling {
			<-notifyCancelDone
		}

		return 1
	}

	fmt.Println("Start running tests:")
	return m.Run()
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func TestAuditSeccomp(t *testing.T) {
	ns := generateTestNamespaceName("test-audit-seccomp")
	spName := "log"

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name: "CreateSeccompProfile",
			cmd: fmt.Sprintf(`
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
			`, spName, ns),
			expectedRegexp: fmt.Sprintf("seccompprofile.security-profiles-operator.x-k8s.io/%s created", spName),
		},
		{
			name: "WaitForSeccompProfile",
			cmd:  fmt.Sprintf("kubectl wait sp --for condition=ready -n %s %s", ns, spName),
		},
		{
			name: "RunSeccompAuditTestPod",
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
			name:           "RunAuditSeccompGadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET audit seccomp -n %s --timeout 15", ns),
			expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+container1\s+\d+\s+unshare\s+unshare\s+kill_thread`, ns),
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestBindsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-bindsnoop")

	t.Parallel()

	bindsnoopCmd := &command{
		name:         "StartBindsnoopGadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET trace bind -n %s -o json", ns),
		startAndStop: true,
		expectedOutputFn: func(output string) error {
			expectedEntry := &bindTypes.Event{
				Event:     buildBaseEvent(ns),
				Comm:      "nc",
				Protocol:  "TCP",
				Addr:      "::",
				Port:      9090,
				Options:   ".R...",
				Interface: "0",
			}

			normalize := func(e *bindTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.MountNsID = 0
			}

			return expectAllToMatch(output, normalize, expectedEntry)
		},
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
			name:           "RunBiolatencyGadget",
			cmd:            "$KUBECTL_GADGET profile block-io --node $(kubectl get node --no-headers | cut -d' ' -f1 | head -1) --timeout 15",
			expectedRegexp: `usecs\s+:\s+count\s+distribution`,
		},
	}

	runCommands(commands, t)
}

func TestBiotop(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running biotop gadget on ARO: see issue #589")
	}

	ns := generateTestNamespaceName("test-biotop")

	t.Parallel()

	biotopCmd := &command{
		name:           "StartBiotopGadget",
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
		name: "StartCapabilitiesGadget",
		// use --audit-only=false to make it work on ARO.
		// See https://github.com/kinvolk/inspektor-gadget/issues/985 for more details.
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace capabilities -n %s --audit-only=false", ns),
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
		name:           "StartDnsGadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace dns -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+OUTGOING\s+A\s+microsoft.com`, ns),
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

func TestEbpftop(t *testing.T) {
	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running top ebpf gadget on AKS Ubuntu amd64: see issue #931")
	}

	t.Parallel()

	ebpftopCmd := &command{
		name:           "StartEbpftopGadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET top ebpf"),
		expectedRegexp: fmt.Sprintf(`\S*\s+\d+\s+Tracing\s+ig_top_ebpf_it\s+\d+\s+\S*\s+`),
		startAndStop:   true,
	}

	commands := []*command{
		ebpftopCmd,
	}

	runCommands(commands, t)
}

func TestExecsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-execsnoop")

	t.Parallel()

	shArgs := []string{"/bin/sh", "-c", "while true; do date && sleep 0.1; done"}
	dateArgs := []string{"/bin/date"}
	sleepArgs := []string{"/bin/sleep", "0.1"}
	// on arm64, trace exec uses kprobe and it cannot trace the arguments:
	// 243759db6b19 ("pkg/gadgets: Use kprobe for execsnoop on arm64.")
	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "arm64" {
		shArgs = nil
		dateArgs = nil
		sleepArgs = nil
	}

	execsnoopCmd := &command{
		name:         "StartExecsnoopGadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET trace exec -n %s -o json", ns),
		startAndStop: true,
		expectedOutputFn: func(output string) error {
			expectedEntries := []*execTypes.Event{
				{
					Event: buildBaseEvent(ns),
					Comm:  "sh",
					Args:  shArgs,
				},
				{
					Event: buildBaseEvent(ns),
					Comm:  "date",
					Args:  dateArgs,
				},
				{
					Event: buildBaseEvent(ns),
					Comm:  "sleep",
					Args:  sleepArgs,
				},
			}

			normalize := func(e *execTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.Ppid = 0
				e.UID = 0
				e.Retval = 0
				e.MountNsID = 0
			}

			return expectEntriesToMatch(output, normalize, expectedEntries...)
		},
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
		name:           "StartFiletopGadget",
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
	fsType := "ext4"
	if *k8sDistro == K8sDistroARO {
		fsType = "xfs"
	}

	ns := generateTestNamespaceName("test-fsslower")

	t.Parallel()

	fsslowerCmd := &command{
		name:           "StartFsslowerGadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace fsslower -n %s -f %s -m 0", ns, fsType),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+cat`, ns),
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
		name:           "StartMountsnoopGadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace mount -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod+\s+mount\s+\d+\s+\d+\s+\d+\s+mount\("/mnt", "/mnt", .*\) = -2`, ns),
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
	nsServer := generateTestNamespaceName("test-networkpolicy-server")
	nsClient := generateTestNamespaceName("test-networkpolicy-client")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(nsServer),
		busyboxPodRepeatCommand(nsServer, "nc -lk -p 9090 -e /bin/cat"),
		{
			name:           "CreateService",
			cmd:            fmt.Sprintf("kubectl expose -n %s pod test-pod --port 9090", nsServer),
			expectedRegexp: "service/test-pod exposed",
		},
		waitUntilTestPodReadyCommand(nsServer),
		createTestNamespaceCommand(nsClient),
		busyboxPodRepeatCommand(nsClient, fmt.Sprintf("echo ok | nc -w 1 test-pod.%s.svc.cluster.local 9090 || true", nsServer)),
		waitUntilTestPodReadyCommand(nsClient),
		{
			name: "RunNetworkPolicyMonitorClient",
			cmd: fmt.Sprintf(`$KUBECTL_GADGET advise network-policy monitor -n %s --output ./networktrace-client.log &
					sleep 10
					kill $!
					head networktrace-client.log | sort | uniq`, nsClient),
			expectedRegexp: fmt.Sprintf(`{"node":".*","namespace":"%s","pod":"test-pod","type":"normal","pktType":"OUTGOING","proto":"tcp","ip":".*","port":9090,"remoteKind":"svc","podHostIP":".*","podIP":".*","podLabels":{"run":"test-pod"},"remoteServiceNamespace":"%s","remoteServiceName":"test-pod","remoteServiceLabelSelector":{"run":"test-pod"}}`, nsClient, nsServer),
		},
		{
			// Docker bridge does not preserve source IP :-(
			// https://github.com/kubernetes/minikube/issues/11211
			// Skip this command with SKIP_TEST if docker is detected
			name: "RunNetworkPolicyMonitorServer",
			cmd: fmt.Sprintf(`$KUBECTL_GADGET advise network-policy monitor -n %s --output ./networktrace-server.log &
					sleep 10
					kill $!
					head networktrace-server.log | sort | uniq
					kubectl get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}'|grep -q docker && echo SKIP_TEST || true`, nsServer),
			expectedRegexp: fmt.Sprintf(`SKIP_TEST|{"node":".*","namespace":"%s","pod":"test-pod","type":"normal","pktType":"HOST","proto":"tcp","ip":".*","port":9090,"remoteKind":"pod","podHostIP":".*","podIP":".*","podLabels":{"run":"test-pod"},"remotePodNamespace":"%s","remotePodName":"test-pod","remotePodLabels":{"run":"test-pod"}}`, nsServer, nsClient),
		},
		{
			name: "RunNetworkPolicyReportClient",
			cmd:  "$KUBECTL_GADGET advise network-policy report --input ./networktrace-client.log",
			expectedRegexp: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: test-pod-network
  namespace: %s
spec:
  egress:
  - ports:
    - port: 9090
      protocol: TCP
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: %s
      podSelector:
        matchLabels:
          run: test-pod
  - ports:
    - port: 53
      protocol: UDP
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: (kube-system|openshift-dns)
      podSelector:
        matchLabels:
          (k8s-app: kube-dns|dns.operator.openshift.io/daemonset-dns: default)
  podSelector:
    matchLabels:
      run: test-pod
  policyTypes:
  - Ingress
  - Egress`, nsClient, nsServer),
		},
		{
			name: "RunNetworkPolicyReportServer",
			cmd: `$KUBECTL_GADGET advise network-policy report --input ./networktrace-server.log
				kubectl get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}'|grep -q docker && echo SKIP_TEST || true`,
			expectedRegexp: fmt.Sprintf(`SKIP_TEST|apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: test-pod-network
  namespace: %s
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: %s
      podSelector:
        matchLabels:
          run: test-pod
    ports:
    - port: 9090
      protocol: TCP
  podSelector:
    matchLabels:
      run: test-pod
  policyTypes:
  - Ingress
  - Egress`, nsServer, nsClient),
		},
		deleteTestNamespaceCommand(nsClient),
		deleteTestNamespaceCommand(nsServer),
	}

	runCommands(commands, t)
}

func TestOomkill(t *testing.T) {
	ns := generateTestNamespaceName("test-oomkill")

	t.Parallel()

	oomkillCmd := &command{
		name:           "StarOomkilGadget",
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
			name:           "RunOomkillTestPod",
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
		name:         "StartOpensnoopGadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET trace open -n %s -o json", ns),
		startAndStop: true,
		expectedOutputFn: func(output string) error {
			expectedEntry := &openTypes.Event{
				Event: buildBaseEvent(ns),
				Comm:  "cat",
				Fd:    3,
				Ret:   3,
				Err:   0,
				Path:  "/dev/null",
			}

			normalize := func(e *openTypes.Event) {
				e.Node = ""
				e.MountNsID = 0
				e.Pid = 0
				e.UID = 0
			}

			return expectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		opensnoopCmd,
		busyboxPodRepeatCommand(ns, "cat /dev/null"),
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestProcessCollector(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running process-collector gadget on ARO: iterators are not supported on kernel 4.18.0-305.19.1.el8_4.x86_64")
	}

	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running process-collector gadget on AKS Ubuntu amd64: iterators are not supported on kernel 5.4.0-1089-azure")
	}

	ns := generateTestNamespaceName("test-process-collector")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		busyboxPodCommand(ns, "nc -l -p 9090"),
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "RunPprocessCollectorGadget",
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
			name:           "RunProfileGadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET profile cpu -n %s -p test-pod -K --timeout 15", ns),
			expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+sh\s+\d`, ns), // echo is builtin.
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
			name:           "RunSeccompAdvisorGadget",
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
		name:         "StartSigsnoopGadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET trace signal -n %s -o json", ns),
		startAndStop: true,
		expectedOutputFn: func(output string) error {
			expectedEntry := &signalTypes.Event{
				Event:  buildBaseEvent(ns),
				Comm:   "sh",
				Signal: "SIGTERM",
			}

			normalize := func(e *signalTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.TargetPid = 0
				e.Retval = 0
				e.MountNsID = 0
			}

			return expectEntriesToMatch(output, normalize, expectedEntry)
		},
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
		name:           "StartSnisnoopGadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET trace sni -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+kinvolk.io`, ns),
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
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running socket-collector gadget on ARO: iterators are not supported on kernel 4.18.0-305.19.1.el8_4.x86_64")
	}

	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running socket-collector gadget on AKS Ubuntu amd64: iterators are not supported on kernel 5.4.0-1089-azure")
	}

	ns := generateTestNamespaceName("test-socket-collector")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		busyboxPodCommand(ns, "nc -l 0.0.0.0 -p 9090"),
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "RunSocketCollectorGadget",
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
		name:           "StartTcpconnectGadget",
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
		name:         "StartTcptracerGadget",
		cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcp -n %s -o json", ns),
		startAndStop: true,
		expectedOutputFn: func(output string) error {
			expectedEntries := []*tcpTypes.Event{
				{
					Event:     buildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     80,
					Operation: "connect",
				},
				{
					Event:     buildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     80,
					Operation: "close",
				},
				{
					Event:     buildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     443,
					Operation: "connect",
				},
			}

			normalize := func(e *tcpTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.Saddr = ""
				e.Sport = 0
				e.MountNsID = 0
			}

			return expectEntriesToMatch(output, normalize, expectedEntries...)
		},
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
		name:           "StartTcptopGadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET top tcp -n %s", ns),
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

// This test is flaky (https://github.com/kinvolk/traceloop/issues/42),
// let's disable it until we rework this gadget
// https://github.com/kinvolk/inspektor-gadget/issues/371
func _TestTraceloop(t *testing.T) {
	ns := generateTestNamespaceName("test-traceloop")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name: "StartTraceloopGadget",
			cmd:  "$KUBECTL_GADGET traceloop start",
		},
		{
			name: "WaitForTraceloopStarted",
			cmd:  "sleep 15",
		},
		{
			name: "RunTraceloopTestPod",
			cmd:  fmt.Sprintf("kubectl run --restart=Never -n %s --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM ; sleep infinity'", ns),
		},
		{
			name: "WaitForTraceloopTestPod",
			cmd:  fmt.Sprintf("sleep 5 ; kubectl wait -n %s --for=condition=ready pod/multiplication ; kubectl get pod -n %s ; sleep 2", ns, ns),
		},
		{
			name:           "CheckTraceloopList",
			cmd:            fmt.Sprintf("sleep 20 ; $KUBECTL_GADGET traceloop list -n %s --no-headers | grep multiplication | awk '{print $1\" \"$6}'", ns),
			expectedString: "multiplication started\n",
		},
		{
			name:           "CheckTraceloopShow",
			cmd:            fmt.Sprintf(`TRACE_ID=$($KUBECTL_GADGET traceloop list -n %s --no-headers | `, ns) + `grep multiplication | awk '{printf "%s", $4}') ; $KUBECTL_GADGET traceloop show $TRACE_ID | grep -C 5 write`,
			expectedRegexp: "\\[bc\\] write\\(1, \"42\\\\n\", 3\\)",
		},
		{
			name:    "PrintTraceloopList",
			cmd:     "$KUBECTL_GADGET traceloop list -A",
			cleanup: true,
		},
		{
			name:           "StopTraceloopGadget",
			cmd:            "$KUBECTL_GADGET traceloop stop",
			expectedString: "",
			cleanup:        true,
		},
		{
			name:    "WaitForTraceloopStopped",
			cmd:     "sleep 15",
			cleanup: true,
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}
