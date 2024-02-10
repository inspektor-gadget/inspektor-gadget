// Copyright 2019-2023 The Inspektor Gadget authors
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
	"fmt"
	"strings"
	"testing"

	tracednsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceDns(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-dns")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("dnstester", *dnsTesterImage, ns, "", ""),
		WaitUntilPodReadyCommand(ns, "dnstester"),
	}
	RunTestSteps(commandsPreTest, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		commands := []*Command{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	dnsServer := GetTestPodIP(t, ns, "dnstester")
	nslookupCmds := []string{
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=a fake.test.com. %s", dnsServer),
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=aaaa fake.test.com. %s", dnsServer),
	}

	commonDataOpts := []CommonDataOption{WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)}
	var extraArgs string
	switch DefaultTestComponent {
	case IgTestComponent:
		extraArgs = "--runtimes=" + containerRuntime
		commonDataOpts = append(commonDataOpts, WithRuntimeMetadata(containerRuntime))
		nslookupCmds = append(nslookupCmds, fmt.Sprintf("setuidgid 1000:1111 nslookup -type=a nodomain.fake.test.com. %s", dnsServer))

	case InspektorGadgetTestComponent:
		extraArgs = "-n " + ns
	}

	// Start the busybox pod so that we can get the IP address of the pod.
	commands := []*Command{
		BusyboxPodRepeatCommand(ns, strings.Join(nslookupCmds, " ; ")),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	busyBoxIP := GetTestPodIP(t, ns, "test-pod")
	traceDNSCmd := &Command{
		Name:         "StartTraceDnsGadget",
		Cmd:          fmt.Sprintf("%s trace dns -o json %s", DefaultTestComponent, extraArgs),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntries := []*tracednsTypes.Event{
				{
					Event:      BuildBaseEvent(ns, commonDataOpts...),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					DstPort:    53,
					SrcIP:      busyBoxIP,
				},
				{
					Event:      BuildBaseEvent(ns, commonDataOpts...),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Rcode:      "NoError",
					Latency:    1,
					NumAnswers: 1,
					Addresses:  []string{"127.0.0.1"},
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					SrcPort:    53,
					DstIP:      busyBoxIP,
				},
				{
					Event:      BuildBaseEvent(ns, commonDataOpts...),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					DstPort:    53,
					SrcIP:      busyBoxIP,
				},
				{
					Event:      BuildBaseEvent(ns, commonDataOpts...),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Rcode:      "NoError",
					Latency:    1,
					NumAnswers: 1,
					Addresses:  []string{"::1"},
					Uid:        1000,
					Gid:        1111,
					Protocol:   "UDP",
					SrcPort:    53,
					DstIP:      busyBoxIP,
				},
			}

			if DefaultTestComponent == IgTestComponent {
				expectedEntries = append(expectedEntries,
					&tracednsTypes.Event{
						Event:      BuildBaseEvent(ns, commonDataOpts...),
						Comm:       "nslookup",
						Qr:         tracednsTypes.DNSPktTypeQuery,
						Nameserver: dnsServer,
						PktType:    "OUTGOING",
						DNSName:    "fake.test.com.",
						QType:      "A",
						Uid:        1000,
						Gid:        1111,
						Protocol:   "UDP",
						DstPort:    53,
						SrcIP:      busyBoxIP,
					},
					&tracednsTypes.Event{
						Event:      BuildBaseEvent(ns, commonDataOpts...),
						Comm:       "nslookup",
						Qr:         tracednsTypes.DNSPktTypeResponse,
						Nameserver: dnsServer,
						PktType:    "HOST",
						DNSName:    "nodomain.fake.test.com.",
						QType:      "A",
						Rcode:      "NXDomain",
						Latency:    1,
						NumAnswers: 0,
						Uid:        1000,
						Gid:        1111,
						Protocol:   "UDP",
						SrcPort:    53,
						DstIP:      busyBoxIP,
					},
				)
			}

			normalize := func(e *tracednsTypes.Event) {
				e.Timestamp = 0
				e.ID = ""
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				// Latency should be > 0 only for DNS responses.
				if e.Latency > 0 {
					e.Latency = 1
				}

				e.Runtime.ContainerID = ""
				e.Runtime.ContainerImageDigest = ""

				if e.Qr == tracednsTypes.DNSPktTypeResponse {
					e.DstPort = 0
					e.SrcIP = ""
				} else {
					e.SrcPort = 0
					e.DstIP = ""
				}

				if DefaultTestComponent == IgTestComponent {
					prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
					if (containerRuntime == ContainerRuntimeDocker || containerRuntime == ContainerRuntimeCRIO) &&
						strings.HasPrefix(e.Runtime.ContainerName, prefixContainerName) {
						e.Runtime.ContainerName = "test-pod"
					}
					if isDockerRuntime {
						e.Runtime.ContainerImageName = ""
					}
				} else if DefaultTestComponent == InspektorGadgetTestComponent {
					e.K8s.Node = ""
					// TODO: Verify container runtime and container name
					e.Runtime.RuntimeName = ""
					e.Runtime.ContainerName = ""
				}

			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
		},
	}

	// Start the trace gadget and verify the output.
	commands = []*Command{
		traceDNSCmd,
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}

func TestTraceDnsHost(t *testing.T) {
	if DefaultTestComponent == InspektorGadgetTestComponent {
		t.Skip("Skip running trace dns --host")
	}

	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-dns")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("dnstester", *dnsTesterImage, ns, "", ""),
		WaitUntilPodReadyCommand(ns, "dnstester"),
	}

	RunTestSteps(commandsPreTest, t)
	dnsServer := GetTestPodIP(t, ns, "dnstester")

	traceDNSCmd := &Command{
		Name:         "TraceDnsHost",
		Cmd:          "ig trace dns -o json --host",
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntries := []*tracednsTypes.Event{
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					// nslookup has several threads and isc-worker0000 will do the DNS
					// request.
					Comm:       "isc-worker0000",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Protocol:   "UDP",
					DstPort:    53,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Comm:       "isc-worker0000",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Protocol:   "UDP",
					DstPort:    53,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Comm:       "isc-worker0000",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Protocol:   "UDP",
					DstPort:    53,
				},
			}

			normalize := func(e *tracednsTypes.Event) {
				e.Timestamp = 0
				e.ID = ""
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				// Latency should be > 0 only for DNS responses.
				if e.Latency > 0 {
					e.Latency = 1
				}

				e.SrcIP = ""
				e.SrcPort = 0
				e.DstIP = ""
				e.Runtime.ContainerImageDigest = ""
			}

			ExpectEntriesToMatch(t, output, normalize, expectedEntries...)
		},
	}

	cmd := fmt.Sprintf(`sh -c 'for i in $(seq 1 30); do nslookup -type=a fake.test.com. %s; nslookup -type=aaaa fake.test.com. %s; done'`, dnsServer, dnsServer)

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceDNSCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		{
			Name:           cmd,
			Cmd:            cmd,
			ExpectedRegexp: dnsServer,
		},
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
