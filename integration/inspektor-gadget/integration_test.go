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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	biotopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
	ebpftopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
	filetopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
	tcptopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	bindTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/types"
	capabilitiesTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	dnsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	execTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	fsslowerType "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"
	mountTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/types"
	networkTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	oomkillTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/types"
	openTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	signalTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	tcpTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/types"
	tcpconnectTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"
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

	if !*doNotDeploySPO {
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
		cleanupCommands = append(cleanupCommands, CleanupSPO)
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

func TestAuditSeccomp(t *testing.T) {
	ns := GenerateTestNamespaceName("test-audit-seccomp")
	spName := "log"

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		{
			Name: "CreateSeccompProfile",
			Cmd: fmt.Sprintf(`
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
  syscalls:
  - action: SCMP_ACT_KILL
    names:
    - unshare
  - action: SCMP_ACT_LOG
    names:
    - mkdir
EOF
			`, spName, ns),
			ExpectedRegexp: fmt.Sprintf("seccompprofile.security-profiles-operator.x-k8s.io/%s created", spName),
		},
		{
			Name: "WaitForSeccompProfile",
			Cmd:  fmt.Sprintf("kubectl wait sp --for condition=ready -n %s %s", ns, spName),
		},
		{
			Name: "RunSeccompAuditTestPod",
			Cmd: fmt.Sprintf(`
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
  terminationGracePeriodSeconds: 0
  containers:
  - name: test-pod-container
    image: busybox
    command: ["sh"]
    args: ["-c", "while true; do unshare -i; sleep 1; done"]
EOF
			`, ns, ns),
			ExpectedRegexp: "pod/test-pod created",
		},
		WaitUntilTestPodReadyCommand(ns),
		{
			Name:           "RunAuditSeccompGadget",
			Cmd:            fmt.Sprintf("$KUBECTL_GADGET audit seccomp -n %s --timeout 15", ns),
			ExpectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod-container\s+\d+\s+unshare\s+unshare\s+kill_thread`, ns),
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestBindsnoop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-bindsnoop")

	t.Parallel()

	bindsnoopCmd := &Command{
		Name:         "StartBindsnoopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace bind -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &bindTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "nc",
				Protocol:  "TCP",
				Addr:      "::",
				Port:      9090,
				Options:   ".R...",
				Interface: "",
			}

			normalize := func(e *bindTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.MountNsID = 0
			}

			return ExpectAllToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		bindsnoopCmd,
		BusyboxPodRepeatCommand(ns, "nc -l -p 9090 -w 1"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestBiolatency(t *testing.T) {
	t.Parallel()

	commands := []*Command{
		{
			Name:           "RunBiolatencyGadget",
			Cmd:            "$KUBECTL_GADGET profile block-io --node $(kubectl get node --no-headers | cut -d' ' -f1 | head -1) --timeout 15",
			ExpectedRegexp: `usecs\s+:\s+count\s+distribution`,
		},
	}

	RunCommands(commands, t)
}

func TestBiotop(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running biotop gadget on ARO: see issue #589")
	}

	ns := GenerateTestNamespaceName("test-biotop")

	t.Parallel()

	biotopCmd := &Command{
		Name:         "StartBiotopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET top block-io -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &biotopTypes.Stats{
				CommonData: BuildCommonData(ns),
				Write:      true,
				Comm:       "dd",
			}

			normalize := func(e *biotopTypes.Stats) {
				e.Node = ""
				e.Major = 0
				e.Minor = 0
				e.MicroSecs = 0
				e.MountNsID = 0
				e.Pid = 0
				e.Operations = 0
				e.Bytes = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		biotopCmd,
		BusyboxPodRepeatCommand(ns, "dd if=/dev/zero of=/tmp/test count=4096"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestCapabilities(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running trace capabilities on ARO: See https://github.com/inspektor-gadget/inspektor-gadget/issues/985 for more details")
	}

	ns := GenerateTestNamespaceName("test-capabilities")

	t.Parallel()

	capabilitiesCmd := &Command{
		Name:         "StartCapabilitiesGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace capabilities -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &capabilitiesTypes.Event{
				Event:   BuildBaseEvent(ns),
				Comm:    "nice",
				CapName: "SYS_NICE",
				Cap:     23,
				Audit:   1,
				Verdict: "Deny",
			}

			normalize := func(e *capabilitiesTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.UID = 0
				e.MountNsID = 0
				// Do not check InsetID to avoid introducing dependency on the kernel version
				e.InsetID = nil
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		capabilitiesCmd,
		BusyboxPodRepeatCommand(ns, "nice -n -20 echo"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestDns(t *testing.T) {
	ns := GenerateTestNamespaceName("test-dns")

	t.Parallel()

	dnsCmd := &Command{
		Name:         "StartDnsGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace dns -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*dnsTypes.Event{
				{
					Event:      BuildBaseEvent(ns),
					ID:         "0000",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					ID:         "0000",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					ID:         "0000",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					ID:         "0000",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "inspektor-gadget.io.",
					QType:      "AAAA",
				},
			}

			// DNS gadget doesn't provide container data. Remove it.
			for _, entry := range expectedEntries {
				entry.Container = ""
			}

			normalize := func(e *dnsTypes.Event) {
				e.Node = ""
				e.ID = "0000"
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		dnsCmd,
		BusyboxPodRepeatCommand(ns,
			"nslookup -type=a inspektor-gadget.io. 8.8.4.4 ;"+
				"nslookup -type=aaaa inspektor-gadget.io. 8.8.4.4"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestEbpftop(t *testing.T) {
	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running top ebpf gadget on AKS Ubuntu amd64: see issue #931")
	}

	t.Parallel()

	ebpftopCmd := &Command{
		Name:         "StartEbpftopGadget",
		Cmd:          "$KUBECTL_GADGET top ebpf -o json",
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &ebpftopTypes.Stats{
				Name: "ig_top_ebpf_it",
				Type: "Tracing",
			}

			normalize := func(e *ebpftopTypes.Stats) {
				e.Node = ""
				e.Namespace = ""
				e.Pod = ""
				e.Container = ""
				e.Namespace = ""
				e.ProgramID = 0
				e.Pids = nil
				e.CurrentRuntime = 0
				e.CurrentRunCount = 0
				e.CumulativeRuntime = 0
				e.CumulativeRunCount = 0
				e.TotalRuntime = 0
				e.TotalRunCount = 0
				e.MapMemory = 0
				e.MapCount = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		ebpftopCmd,
	}

	RunCommands(commands, t)
}

func TestExecsnoop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-execsnoop")

	t.Parallel()

	cmd := "while true; do date ; sleep 0.1; done"
	shArgs := []string{"/bin/sh", "-c", cmd}
	dateArgs := []string{"/bin/date"}
	sleepArgs := []string{"/bin/sleep", "0.1"}
	// on arm64, trace exec uses kprobe and it cannot trace the arguments:
	// 243759db6b19 ("pkg/gadgets: Use kprobe for execsnoop on arm64.")
	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "arm64" {
		shArgs = nil
		dateArgs = nil
		sleepArgs = nil
	}

	execsnoopCmd := &Command{
		Name:         "StartExecsnoopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace exec -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*execTypes.Event{
				{
					Event: BuildBaseEvent(ns),
					Comm:  "sh",
					Args:  shArgs,
				},
				{
					Event: BuildBaseEvent(ns),
					Comm:  "date",
					Args:  dateArgs,
				},
				{
					Event: BuildBaseEvent(ns),
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

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		execsnoopCmd,
		BusyboxPodCommand(ns, cmd),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestFiletop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-filetop")

	t.Parallel()

	filetopCmd := &Command{
		Name:         "StartFiletopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET top file -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &filetopTypes.Stats{
				CommonData: BuildCommonData(ns),
				Reads:      0,
				ReadBytes:  0,
				Filename:   "date.txt",
				FileType:   byte('R'), // Regular file
				Comm:       "sh",
			}

			normalize := func(e *filetopTypes.Stats) {
				e.Node = ""
				e.Writes = 0
				e.WriteBytes = 0
				e.Pid = 0
				e.Tid = 0
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		filetopCmd,
		BusyboxPodRepeatCommand(ns, "echo date >> /tmp/date.txt"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestFsslower(t *testing.T) {
	fsType := "ext4"
	if *k8sDistro == K8sDistroARO {
		fsType = "xfs"
	}

	ns := GenerateTestNamespaceName("test-fsslower")

	t.Parallel()

	fsslowerCmd := &Command{
		Name:         "StartFsslowerGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace fsslower -n %s -f %s -m 0 -o json", ns, fsType),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &fsslowerType.Event{
				Event: BuildBaseEvent(ns),
				Comm:  "cat",
				File:  "foo",
				Op:    "R",
			}

			normalize := func(e *fsslowerType.Event) {
				e.Node = ""
				e.MountNsID = 0
				e.Pid = 0
				e.Bytes = 0
				e.Offset = 0
				e.Latency = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		fsslowerCmd,
		BusyboxPodCommand(ns, "echo 'this is foo' > foo && while true; do cat foo && sleep 0.1; done"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestMountsnoop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-mountsnoop")

	t.Parallel()

	mountsnoopCmd := &Command{
		Name:         "StartMountsnoopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace mount -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &mountTypes.Event{
				Event:     BuildBaseEvent(ns),
				Comm:      "mount",
				Operation: "mount",
				Retval:    -2,
				Source:    "/mnt",
				Target:    "/mnt",
			}

			normalize := func(e *mountTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.Tid = 0
				e.MountNsID = 0
				e.Latency = 0
				e.Fs = ""
				e.Data = ""
				e.Flags = nil
				e.FlagsRaw = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		mountsnoopCmd,
		BusyboxPodRepeatCommand(ns, "mount /mnt /mnt"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
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
			ExpectedRegexp: fmt.Sprintf(`{"node":".*","namespace":"%s","pod":"test-pod","type":"normal","pktType":"OUTGOING","proto":"tcp","addr":".*","port":9090,"remoteKind":"svc","podHostIP":".*","podIP":".*","podLabels":{"run":"test-pod"},"remoteServiceNamespace":"%s","remoteServiceName":"test-pod","remoteServiceLabelSelector":{"run":"test-pod"}}`, nsClient, nsServer),
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
			ExpectedRegexp: fmt.Sprintf(`SKIP_TEST|{"node":".*","namespace":"%s","pod":"test-pod","type":"normal","pktType":"HOST","proto":"tcp","addr":".*","port":9090,"remoteKind":"pod","podHostIP":".*","podIP":".*","podLabels":{"run":"test-pod"},"remotePodNamespace":"%s","remotePodName":"test-pod","remotePodLabels":{"run":"test-pod"}}`, nsServer, nsClient),
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
	}

	RunCommands(commands, t)
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

	RunCommands(commands, t)
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

	RunCommands(commands, t)
}

func TestNetworkGraph(t *testing.T) {
	ns := GenerateTestNamespaceName("test-networkgraph")

	t.Parallel()

	networkGraphCmd := &Command{
		Name:         "StartNetworkGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace network -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*networkTypes.Event{
				{
					Event:       BuildBaseEvent(ns),
					PktType:     "OUTGOING",
					Proto:       "tcp",
					Port:        80,
					Addr:        "1.1.1.1",
					PodLabels:   map[string]string{"run": "test-pod"},
					RemoteKind:  "other",
					RemoteOther: "1.1.1.1",
				},
				{
					Event:      BuildBaseEvent(ns),
					PktType:    "OUTGOING",
					Proto:      "udp",
					Port:       53,
					PodLabels:  map[string]string{"run": "test-pod"},
					RemoteKind: "svc",
				},
			}
			// Network gadget doesn't provide container data. Remove it.
			for _, entry := range expectedEntries {
				entry.Container = ""
			}

			normalize := func(e *networkTypes.Event) {
				e.Node = ""
				e.Container = ""
				e.PodHostIP = ""
				e.PodIP = ""
				e.PodOwner = ""
				e.RemoteSvcNamespace = ""
				e.RemoteSvcName = ""
				e.RemoteSvcLabelSelector = nil

				if e.RemoteKind == "svc" {
					e.Addr = ""
				}
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		networkGraphCmd,
		BusyboxPodRepeatCommand(ns, "wget -q -O /dev/null 1.1.1.1.nip.io"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestProcessCollector(t *testing.T) {
	if *k8sDistro == K8sDistroARO {
		t.Skip("Skip running process-collector gadget on ARO: iterators are not supported on kernel 4.18.0-305.19.1.el8_4.x86_64")
	}

	if *k8sDistro == K8sDistroAKSUbuntu && *k8sArch == "amd64" {
		t.Skip("Skip running process-collector gadget on AKS Ubuntu amd64: iterators are not supported on kernel 5.4.0-1089-azure")
	}

	ns := GenerateTestNamespaceName("test-process-collector")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "nc -l -p 9090"),
		WaitUntilTestPodReadyCommand(ns),
		{
			Name:           "RunPprocessCollectorGadget",
			Cmd:            fmt.Sprintf("$KUBECTL_GADGET snapshot process -n %s", ns),
			ExpectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+nc\s+\d+`, ns),
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestProfile(t *testing.T) {
	ns := GenerateTestNamespaceName("test-profile")

	t.Parallel()

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		BusyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
		WaitUntilTestPodReadyCommand(ns),
		{
			Name:           "RunProfileGadget",
			Cmd:            fmt.Sprintf("$KUBECTL_GADGET profile cpu -n %s -p test-pod -K --timeout 15", ns),
			ExpectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+sh\s+\d`, ns), // echo is builtin.
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
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

	RunCommands(commands, t)
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

	RunCommands(commands, t)
}

func TestSnisnoop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-snisnoop")

	t.Parallel()

	snisnoopCmd := &Command{
		Name:           "StartSnisnoopGadget",
		Cmd:            fmt.Sprintf("$KUBECTL_GADGET trace sni -n %s", ns),
		ExpectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+kinvolk.io`, ns),
		StartAndStop:   true,
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		snisnoopCmd,
		BusyboxPodRepeatCommand(ns, "wget -q -O /dev/null https://kinvolk.io"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
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
			Name:           "RunSocketCollectorGadget",
			Cmd:            fmt.Sprintf("$KUBECTL_GADGET snapshot socket -n %s", ns),
			ExpectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+TCP\s+0\.0\.0\.0`, ns),
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestTcpconnect(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcpconnect")

	t.Parallel()

	tcpconnectCmd := &Command{
		Name:         "StartTcpconnectGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcpconnect -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*tcpconnectTypes.Event{
				{
					Event:     BuildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     80,
				},
				{
					Event:     BuildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     443,
				},
			}

			normalize := func(e *tcpconnectTypes.Event) {
				e.Node = ""
				e.Pid = 0
				e.Saddr = ""
				e.MountNsID = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		tcpconnectCmd,
		BusyboxPodRepeatCommand(ns, "wget -q -O /dev/null -T 3 http://1.1.1.1"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestTcptracer(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcptracer")

	t.Parallel()

	tcptracerCmd := &Command{
		Name:         "StartTcptracerGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace tcp -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*tcpTypes.Event{
				{
					Event:     BuildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     80,
					Operation: "connect",
				},
				{
					Event:     BuildBaseEvent(ns),
					Comm:      "wget",
					IPVersion: 4,
					Daddr:     "1.1.1.1",
					Dport:     80,
					Operation: "close",
				},
				{
					Event:     BuildBaseEvent(ns),
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

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		tcptracerCmd,
		BusyboxPodRepeatCommand(ns, "wget -q -O /dev/null -T 3 http://1.1.1.1"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

func TestTcptop(t *testing.T) {
	ns := GenerateTestNamespaceName("test-tcptop")

	t.Parallel()

	tcptopCmd := &Command{
		Name:         "StartTcptopGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET top tcp -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &tcptopTypes.Stats{
				CommonData: BuildCommonData(ns),
				Daddr:      "1.1.1.1",
				Comm:       "wget",
				Dport:      80,
				Family:     syscall.AF_INET,
			}

			normalize := func(e *tcptopTypes.Stats) {
				e.Node = ""
				e.Saddr = ""
				e.MountNsID = 0
				e.Pid = 0
				e.Sport = 0
				e.Sent = 0
				e.Received = 0
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		tcptopCmd,
		BusyboxPodRepeatCommand(ns, "wget -q -O /dev/null 1.1.1.1"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}

// This test is flaky (https://github.com/kinvolk/traceloop/issues/42),
// let's disable it until we rework this gadget
// https://github.com/inspektor-gadget/inspektor-gadget/issues/371
func _TestTraceloop(t *testing.T) {
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
			Cmd:            fmt.Sprintf("sleep 20 ; $KUBECTL_GADGET traceloop list -n %s --no-headers | grep multiplication | awk '{print $1\" \"$6}'", ns),
			ExpectedString: "multiplication started\n",
		},
		{
			Name:           "CheckTraceloopShow",
			Cmd:            fmt.Sprintf(`TRACE_ID=$($KUBECTL_GADGET traceloop list -n %s --no-headers | `, ns) + `grep multiplication | awk '{printf "%s", $4}') ; $KUBECTL_GADGET traceloop show $TRACE_ID | grep -C 5 write`,
			ExpectedRegexp: "\\[bc\\] write\\(1, \"42\\\\n\", 3\\)",
		},
		{
			Name:    "PrintTraceloopList",
			Cmd:     "$KUBECTL_GADGET traceloop list -A",
			Cleanup: true,
		},
		{
			Name:           "StopTraceloopGadget",
			Cmd:            "$KUBECTL_GADGET traceloop stop",
			ExpectedString: "",
			Cleanup:        true,
		},
		{
			Name:    "WaitForTraceloopStopped",
			Cmd:     "sleep 15",
			Cleanup: true,
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunCommands(commands, t)
}
