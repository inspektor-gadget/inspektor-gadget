// Copyright 2022 The Inspektor Gadget authors
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

	traceDNSCmd := &Command{
		Name:         "TraceDns",
		Cmd:          fmt.Sprintf("local-gadget trace dns -o json --runtimes=%s", *containerRuntime),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*dnsTypes.Event{
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
					Rcode:      "NoError",
					Latency:    1,
				},
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "inspektor-gadget.io.",
					QType:      "AAAA",
				},
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "inspektor-gadget.io.",
					QType:      "AAAA",
					Rcode:      "NoError",
					Latency:    1,
				},
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeQuery,
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "nodomain.inspektor-gadget.io.",
					QType:      "A",
				},
				{
					Event:      BuildBaseEvent(ns),
					Comm:       "nslookup",
					Qr:         dnsTypes.DNSPktTypeResponse,
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "nodomain.inspektor-gadget.io.",
					QType:      "A",
					Rcode:      "NXDomain",
					Latency:    1,
				},
			}

			normalize := func(e *dnsTypes.Event) {
				// TODO: Handle it once we support getting K8s container name for docker
				// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/737
				if *containerRuntime == ContainerRuntimeDocker {
					e.Container = "test-pod"
				}
				e.Timestamp = 0
				e.ID = ""
				e.MountNsID = 0
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
		"nslookup -type=a inspektor-gadget.io. 8.8.4.4",
		"nslookup -type=aaaa inspektor-gadget.io. 8.8.4.4",
		"nslookup -type=a nodomain.inspektor-gadget.io. 8.8.4.4",
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceDNSCmd,
		SleepForSecondsCommand(2), // wait to ensure local-gadget has started
		BusyboxPodRepeatCommand(ns, strings.Join(nslookupCmds, " ; ")),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t)
}
