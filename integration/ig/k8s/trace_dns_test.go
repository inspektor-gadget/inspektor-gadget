// Copyright 2022-2023 The Inspektor Gadget authors
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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	dnsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

func TestTraceDns(t *testing.T) {
	t.Parallel()
	ns := GenerateTestNamespaceName("test-trace-dns")

	commandsPreTest := []*Command{
		CreateTestNamespaceCommand(ns),
		PodCommand("dnstester", *dnsTesterImage, ns, "", ""),
		WaitUntilPodReadyCommand(ns, "dnstester"),
	}

	RunTestSteps(commandsPreTest, t)
	dnsServer, err := GetTestPodIP(ns, "dnstester")
	if err != nil {
		t.Fatalf("failed to get pod ip: %v", err)
	}

	traceDNSCmd := &Command{
		Name:         "TraceDns",
		Cmd:          fmt.Sprintf("ig trace dns -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*dnsTypes.Event{
				{
					Event:      BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Uid:        1000,
					Gid:        1111,
				},
				{
					Event:      BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
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
				},
				{
					Event:      BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Uid:        1000,
					Gid:        1111,
				},
				{
					Event:      BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
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
				},
				{
					Event:      BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Uid:        1000,
					Gid:        1111,
				},
				{
					Event:      BuildBaseEvent(ns, WithRuntimeMetadata(*containerRuntime)),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "nodomain.fake.test.com.",
					QType:      "A",
					Rcode:      "NXDomain",
					Latency:    1,
					NumAnswers: 0,
					Uid:        1000,
					Gid:        1111,
				},
			}

			normalize := func(e *dnsTypes.Event) {
				// Docker and CRI-O uses a custom container name composed, among
				// other things, by the pod UID. We don't know the pod UID in
				// advance, so we can't match the exact expected container name.
				prefixContainerName := "k8s_" + "test-pod" + "_" + "test-pod" + "_" + ns + "_"
				if (*containerRuntime == ContainerRuntimeDocker || *containerRuntime == ContainerRuntimeCRIO) &&
					strings.HasPrefix(e.Runtime.Container, prefixContainerName) {
					e.Runtime.Container = "test-pod"
				}

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
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	nslookupCmds := []string{
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=a fake.test.com. %s", dnsServer),
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=aaaa fake.test.com. %s", dnsServer),
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=a nodomain.fake.test.com. %s", dnsServer),
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceDNSCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		BusyboxPodRepeatCommand(ns, strings.Join(nslookupCmds, " ; ")),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
