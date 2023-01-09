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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	cpuprofileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
	processCollectorTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	socketCollectorTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	tcptopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	oomkillTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/types"
	openTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	signalTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	sniTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/types"
	tcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
	tcpconnectTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"
)

const (
	K8sDistroAKSMariner = "aks-Mariner"
	K8sDistroAKSUbuntu  = "aks-Ubuntu"
	K8sDistroARO        = "aro"
	K8sDistroMinikubeGH = "minikube-github"
)

const securityProfileOperatorNamespace = "security-profiles-operator"

var (
	supportedK8sDistros = []string{K8sDistroAKSMariner, K8sDistroAKSUbuntu, K8sDistroARO, K8sDistroMinikubeGH}
	cleaningUp          = uint32(0)
)

var (
	integration = flag.Bool("integration", false, "run integration tests")

	// image such as ghcr.io/inspektor-gadget/inspektor-gadget:latest
	image = flag.String("image", "", "gadget container image")

	doNotDeployIG  = flag.Bool("no-deploy-ig", false, "don't deploy Inspektor Gadget")
	doNotDeploySPO = flag.Bool("no-deploy-spo", false, "don't deploy the Security Profiles Operator (SPO)")

	k8sDistro = flag.String("k8s-distro", "", "allows to skip tests that are not supported on a given Kubernetes distribution")
	k8sArch   = flag.String("k8s-arch", "amd64", "allows to skip tests that are not supported on a given CPU architecture")
)

func cleanupFunc(cleanupCommands []*Command) {
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
		err := cmd.StartWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
	}

	for _, cmd := range cleanupCommands {
		err := cmd.WaitWithoutTest()
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

	initCommands := []*Command{}
	cleanupCommands := []*Command{DeleteRemainingNamespacesCommand()}

	if !*doNotDeployIG {
		imagePullPolicy := "Always"
		if *k8sDistro == K8sDistroMinikubeGH {
			imagePullPolicy = "Never"
		}
		deployCmd := DeployInspektorGadget(*image, imagePullPolicy)
		initCommands = append(initCommands, deployCmd)

		cleanupCommands = append(cleanupCommands, CleanupInspektorGadget)
	}

	deploySPO := !CheckNamespace(securityProfileOperatorNamespace) && !*doNotDeploySPO
	if deploySPO {
		limitReplicas := false
		patchWebhookConfig := false
		bestEffortResourceMgmt := false
		if *k8sDistro == K8sDistroMinikubeGH {
			limitReplicas = true
			bestEffortResourceMgmt = true
		}
		if *k8sDistro == K8sDistroAKSUbuntu {
			patchWebhookConfig = true
		}
		initCommands = append(initCommands, DeploySPO(limitReplicas, patchWebhookConfig, bestEffortResourceMgmt))
		cleanupCommands = append(cleanupCommands, CleanupSPO...)
	}

	if CheckNamespace(securityProfileOperatorNamespace) {
		fmt.Println("Using existing installation of SPO in the cluster:")
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
					err := cmd.KillWithoutTest()
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

		err := cmd.RunWithoutTest()
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

func TestNetworkpolicy(t *testing.T) {
	nsServer := GenerateTestNamespaceName("test-networkpolicy-server")
	nsClient := GenerateTestNamespaceName("test-networkpolicy-client")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(nsServer),
		BusyboxPodRepeatCommand(nsServer, "nc -lk -p 9090 -e /bin/cat"),
		{
			Name:           "CreateService",
			Cmd:            fmt.Sprintf("kubectl expose -n %s pod test-pod --port 9090", nsServer),
			ExpectedRegexp: "service/test-pod exposed",
		},
		WaitUntilTestPodReadyCommand(nsServer),
		CreateTestNamespaceCommand(nsClient),
		BusyboxPodRepeatCommand(nsClient, fmt.Sprintf("echo ok | nc -w 1 test-pod.%s.svc.cluster.local 9090 || true", nsServer)),
		WaitUntilTestPodReadyCommand(nsClient),
		{
			Name: "RunNetworkPolicyMonitorClient",
			Cmd: fmt.Sprintf(`$KUBECTL_GADGET advise network-policy monitor -n %s --output ./networktrace-client.log &
					sleep 10
					kill $!
					head networktrace-client.log | sort | uniq`, nsClient),
			ExpectedRegexp: fmt.Sprintf(`{"node":".*","namespace":"%s","pod":"test-pod","container":"test-pod","type":"normal","pktType":"OUTGOING","proto":"tcp","port":9090,"podHostIP":".*","podIP":".*","podLabels":{"run":"test-pod"},"remoteKind":"svc","remoteAddr":".*","remoteName":"test-pod","remoteNamespace":"%s","remoteLabels":{"run":"test-pod"}}`, nsClient, nsServer),
		},
		{
			// Docker bridge does not preserve source IP :-(
			// https://github.com/kubernetes/minikube/issues/11211
			// Skip this command with SKIP_TEST if docker is detected
			Name: "RunNetworkPolicyMonitorServer",
			Cmd: fmt.Sprintf(`$KUBECTL_GADGET advise network-policy monitor -n %s --output ./networktrace-server.log &
					sleep 10
					kill $!
					head networktrace-server.log | sort | uniq
					kubectl get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}'|grep -q docker && echo SKIP_TEST || true`, nsServer),
			ExpectedRegexp: fmt.Sprintf(`SKIP_TEST|{"node":".*","namespace":"%s","pod":"test-pod","container":"test-pod","type":"normal","pktType":"HOST","proto":"tcp","port":9090,"podHostIP":".*","podIP":".*","podLabels":{"run":"test-pod"},"remoteKind":"pod","remoteAddr":".*","remoteName":"test-pod","remoteNamespace":"%s","remoteLabels":{"run":"test-pod"}}`, nsServer, nsClient),
		},
		{
			Name: "RunNetworkPolicyReportClient",
			Cmd:  "$KUBECTL_GADGET advise network-policy report --input ./networktrace-client.log",
			ExpectedRegexp: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
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
			Name: "RunNetworkPolicyReportServer",
			Cmd: `$KUBECTL_GADGET advise network-policy report --input ./networktrace-server.log
				kubectl get node -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}'|grep -q docker && echo SKIP_TEST || true`,
			ExpectedRegexp: fmt.Sprintf(`SKIP_TEST|apiVersion: networking.k8s.io/v1
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
		DeleteTestNamespaceCommand(nsClient),
		DeleteTestNamespaceCommand(nsServer),
		{
			Name:    "CleanupLogFiles",
			Cmd:     "rm -f networktrace-client.log networktrace-server.log",
			Cleanup: true,
		},
	}

	RunTestSteps(commands, t)
}

func TestOomkill(t *testing.T) {
	ns := GenerateTestNamespaceName("test-oomkill")

	t.Parallel()

	oomkillCmd := &Command{
		Name:         "StartOomkilGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace oomkill -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &oomkillTypes.Event{
				Event:      BuildBaseEvent(ns),
				KilledComm: "tail",
			}
			expectedEntry.Container = "test-pod-container"

			normalize := func(e *oomkillTypes.Event) {
				e.Node = ""
				e.KilledPid = 0
				e.Pages = 0
				e.TriggeredPid = 0
				e.TriggeredComm = ""
				e.MountNsID = 0
			}

			return ExpectAllToMatch(output, normalize, expectedEntry)
		},
	}

	limitPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
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

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		oomkillCmd,
		{
			Name:           "RunOomkillTestPod",
			Cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", limitPodYaml),
			ExpectedRegexp: "pod/test-pod created",
		},
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestOpensnoop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-opensnoop")

	t.Parallel()

	opensnoopCmd := &Command{
		Name:         "StartOpensnoopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace open -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &openTypes.Event{
				Event: BuildBaseEvent(ns),
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

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		opensnoopCmd,
		BusyboxPodRepeatCommand(ns, "cat /dev/null"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestNetworkGraph(t *testing.T) {
	ns := GenerateTestNamespaceName("test-networkgraph")

	t.Parallel()

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	networkGraphCmd := &Command{
		Name:         "StartNetworkGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace network -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			TestPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntry := &networkTypes.Event{
				Event:           BuildBaseEvent(ns),
				PktType:         "OUTGOING",
				Proto:           "tcp",
				RemoteAddr:      NginxIP,
				Port:            80,
				RemoteKind:      networkTypes.RemoteKindPod,
				PodIP:           TestPodIP,
				PodLabels:       map[string]string{"run": "test-pod"},
				RemoteNamespace: ns,
				RemoteName:      "nginx-pod",
				RemoteLabels:    map[string]string{"run": "nginx-pod"},
			}

			normalize := func(e *networkTypes.Event) {
				e.Node = ""
				e.PodHostIP = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		networkGraphCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestProcessCollector(t *testing.T) {
	ns := GenerateTestNamespaceName("test-process-collector")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -l -p 9090"),
		WaitUntilTestPodReadyCommand(ns),
		{
			Name: "RunProcessCollectorGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET snapshot process -n %s -o json", ns),
			ExpectedOutputFn: func(output string) error {
				expectedEntry := &processCollectorTypes.Event{
					Event:   BuildBaseEvent(ns),
					Command: "nc",
				}

				normalize := func(e *processCollectorTypes.Event) {
					e.Node = ""
					e.Pid = 0
					e.Tid = 0
					e.ParentPid = 0
					e.MountNsID = 0
				}

				return ExpectEntriesInArrayToMatch(output, normalize, expectedEntry)
			},
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestCpuProfile(t *testing.T) {
	ns := GenerateTestNamespaceName("test-cpu-profile")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
		WaitUntilTestPodReadyCommand(ns),
		{
			Name: "RunProfileGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET profile cpu -n %s -p test-pod -K --timeout 15 -o json", ns),
			ExpectedOutputFn: func(output string) error {
				expectedEntry := &cpuprofileTypes.Report{
					CommonData: BuildCommonData(ns),
					Comm:       "sh",
				}

				normalize := func(e *cpuprofileTypes.Report) {
					e.Node = ""
					e.Pid = 0
					e.UserStack = nil
					e.KernelStack = nil
					e.Count = 0
				}

				return ExpectEntriesToMatch(output, normalize, expectedEntry)
			},
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestSeccompadvisor(t *testing.T) {
	ns := GenerateTestNamespaceName("test-seccomp-advisor")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodRepeatCommand(ns, "echo foo"),
		WaitUntilTestPodReadyCommand(ns),
		{
			Name:           "RunSeccompAdvisorGadget",
			Cmd:            fmt.Sprintf("id=$($KUBECTL_GADGET advise seccomp-profile start -n %s -p test-pod); sleep 30; $KUBECTL_GADGET advise seccomp-profile stop $id", ns),
			ExpectedRegexp: `write`,
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestSigsnoop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-sigsnoop")

	t.Parallel()

	sigsnoopCmd := &Command{
		Name:         "StartSigsnoopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace signal -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &signalTypes.Event{
				Event:  BuildBaseEvent(ns),
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

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		sigsnoopCmd,
		BusyboxPodRepeatCommand(ns, "sleep 3 & kill $!"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestSnisnoop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-snisnoop")

	t.Parallel()

	snisnoopCmd := &Command{
		Name:         "StartSnisnoopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace sni -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &sniTypes.Event{
				Event: BuildBaseEvent(ns),
				Name:  "inspektor-gadget.io",
			}

			// SNI gadget doesn't provide container data. Remove it.
			expectedEntry.Container = ""

			normalize := func(e *sniTypes.Event) {
				e.Node = ""
			}

			return ExpectAllToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		snisnoopCmd,
		BusyboxPodRepeatCommand(ns, "wget -q -O /dev/null https://inspektor-gadget.io"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestSocketCollector(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running socket-collector gadget on ARO: iterators are not supported on kernel 4.18.0-305.19.1.el8_4.x86_64")
	}

	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running socket-collector gadget on AKS Ubuntu amd64: iterators are not supported on kernel 5.4.0-1089-azure")
	}

	ns := GenerateTestNamespaceName("test-socket-collector")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -l 0.0.0.0 -p 9090"),
		WaitUntilTestPodReadyCommand(ns),
		{
			Name: "RunSocketCollectorGadget",
			Cmd:  fmt.Sprintf("$KUBECTL_GADGET snapshot socket -n %s -o json", ns),
			ExpectedOutputFn: func(output string) error {
				expectedEntry := &socketCollectorTypes.Event{
					Event:         BuildBaseEvent(ns),
					Protocol:      "TCP",
					LocalAddress:  "0.0.0.0",
					LocalPort:     9090,
					RemoteAddress: "0.0.0.0",
					RemotePort:    0,
					Status:        "LISTEN",
				}

				// Socket gadget doesn't provide container data yet. See issue #744.
				expectedEntry.Container = ""

				normalize := func(e *socketCollectorTypes.Event) {
					e.Node = ""
					e.Container = ""
					e.InodeNumber = 0
				}

				return ExpectEntriesInArrayToMatch(output, normalize, expectedEntry)
			},
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestTcpconnect(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcpconnect")

	t.Parallel()

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	tcpconnectCmd := &Command{
		Name:         "StartTcpconnectGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcpconnect -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			TestPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntry := &tcpconnectTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "wget",
				IPVersion: 4,
				Dport:     80,
				Saddr:     TestPodIP,
				Daddr:     NginxIP,
			}

			normalize := func(e *tcpconnectTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		tcpconnectCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestTcptracer(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcptracer")

	t.Parallel()

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	tcptracerCmd := &Command{
		Name:         "StartTcptracerGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcp -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			TestPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntry := &tcpTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "wget",
				IPVersion: 4,
				Dport:     80,
				Operation: "connect",
				Saddr:     TestPodIP,
				Daddr:     NginxIP,
			}

			normalize := func(e *tcpTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.Sport = 0
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		tcptracerCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

func TestTcptop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcptop")

	t.Parallel()

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("nginx-pod", "nginx", ns, "", ""),
		WaitUntilPodReadyCommand(ns, "nginx-pod"),
	}

	RunTestSteps(commandsPreTest, t)
	NginxIP := GetTestPodIP(ns, "nginx-pod")

	tcptopCmd := &Command{
		Name:         "StartTcptopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET top tcp -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			TestPodIP := GetTestPodIP(ns, "test-pod")

			expectedEntry := &tcptopTypes.Stats{
				CommonData: BuildCommonData(ns),
				Comm:       "wget",
				Dport:      80,
				Family:     syscall.AF_INET,
				Saddr:      TestPodIP,
				Daddr:      NginxIP,
			}

			normalize := func(e *tcptopTypes.Stats) {
				e.Node = ""
				e.MountNsID = 0
				e.Pid = 0
				e.Sport = 0
				e.Sent = 0
				e.Received = 0
			}

			return ExpectEntriesInMultipleArrayToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		tcptopCmd,
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", NginxIP)),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}

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
