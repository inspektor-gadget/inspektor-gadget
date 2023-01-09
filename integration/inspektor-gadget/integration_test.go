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
	socketCollectorTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	tcptopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
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
