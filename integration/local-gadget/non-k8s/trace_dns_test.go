// Copyright 2023 The Inspektor Gadget authors
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
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	dnsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTraceDns(t *testing.T) {
	t.Parallel()
	cn := "test-trace-dns"

	traceDNSCmd := &Command{
		Name:         "TraceDns",
		Cmd:          fmt.Sprintf("./local-gadget trace dns -o json --runtimes=docker -c %s", cn),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntries := []*dnsTypes.Event{
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Container: cn,
						},
					},
					Qr:         dnsTypes.DNSPktTypeQuery,
					Comm:       "nslookup",
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Container: cn,
						},
					},
					Qr:         dnsTypes.DNSPktTypeResponse,
					Comm:       "nslookup",
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "inspektor-gadget.io.",
					QType:      "A",
					Rcode:      "NoError",
					Latency:    1,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Container: cn,
						},
					},
					Qr:         dnsTypes.DNSPktTypeQuery,
					Comm:       "nslookup",
					Nameserver: "8.8.4.4",
					PktType:    "OUTGOING",
					DNSName:    "inspektor-gadget.io.",
					QType:      "AAAA",
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Container: cn,
						},
					},
					Qr:         dnsTypes.DNSPktTypeResponse,
					Comm:       "nslookup",
					Nameserver: "8.8.4.4",
					PktType:    "HOST",
					DNSName:    "inspektor-gadget.io.",
					QType:      "AAAA",
					Rcode:      "NoError",
					Latency:    1,
				},
			}

			normalize := func(e *dnsTypes.Event) {
				e.ID = ""
				e.Timestamp = 0
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

	testSteps := []TestStep{
		traceDNSCmd,
		SleepForSecondsCommand(2), // wait to ensure local-gadget has started
		&DockerContainer{
			Name: cn,
			Cmd: "nslookup -type=a inspektor-gadget.io. 8.8.4.4 ; " +
				"nslookup -type=aaaa inspektor-gadget.io. 8.8.4.4",
		},
	}

	RunTestSteps(testSteps, t)
}
