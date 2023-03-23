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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestTraceDns(t *testing.T) {
	ns := GenerateTestNamespaceName("test-trace-dns")

	t.Parallel()

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
		Name:         "StartTraceDnsGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET trace dns -n %s -o json", ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*tracednsTypes.Event{
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Rcode:      "NoError",
					Latency:    1,
				},
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeQuery,
					Nameserver: dnsServer,
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         tracednsTypes.DNSPktTypeResponse,
					Nameserver: dnsServer,
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Rcode:      "NoError",
					Latency:    1,
				},
			}

			normalize := func(e *tracednsTypes.Event) {
				e.Timestamp = 0
				e.Node = ""
				e.ID = ""
				e.MountNsID = 0
				e.NetNsID = 0
				e.Pid = 0
				e.Tid = 0

				// Latency should be > 0 only for DNS responses.
				if e.Latency > 0 {
					e.Latency = 1
				}
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntries...)
		},
	}

	nslookupCmds := []string{
		fmt.Sprintf("nslookup -type=a fake.test.com. %s", dnsServer),
		fmt.Sprintf("nslookup -type=aaaa fake.test.com. %s", dnsServer),
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceDNSCmd,
		BusyboxPodRepeatCommand(ns, strings.Join(nslookupCmds, " ; ")),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
