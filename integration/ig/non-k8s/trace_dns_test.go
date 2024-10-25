// Copyright 2023-2024 The Inspektor Gadget authors
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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newTraceDnsSteps(cn string, dnsServerArgs string) []TestStep {
	// dnsTesterImage (image dnstester) has the following symlink:
	// /usr/bin/nslookup -> /bin/busybox
	exepath := "/bin/busybox"

	traceDNSCmd := &Command{
		Name:         "TraceDns",
		Cmd:          fmt.Sprintf("./ig trace dns --paths -o json --runtimes=%s -c %s", *runtime, cn),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntries := []*dnsTypes.Event{
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								RuntimeName:   eventtypes.String2RuntimeName(*runtime),
								ContainerName: cn,
							},
						},
					},
					Qr:         dnsTypes.DNSPktTypeQuery,
					Cwd:        "/",
					Pcomm:      "sh",
					Exepath:    exepath,
					Comm:       "nslookup",
					Nameserver: "127.0.0.1",
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Protocol:   "UDP",
					DstPort:    53,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								RuntimeName:   eventtypes.String2RuntimeName(*runtime),
								ContainerName: cn,
							},
						},
					},
					Qr:         dnsTypes.DNSPktTypeResponse,
					Cwd:        "/",
					Pcomm:      "sh",
					Exepath:    exepath,
					Comm:       "nslookup",
					Nameserver: "127.0.0.1",
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "A",
					Rcode:      "No Error",
					Latency:    1,
					NumAnswers: 1,
					Addresses:  []string{"127.0.0.1"},
					Protocol:   "UDP",
					SrcPort:    53,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								RuntimeName:   eventtypes.String2RuntimeName(*runtime),
								ContainerName: cn,
							},
						},
					},
					Qr:         dnsTypes.DNSPktTypeQuery,
					Cwd:        "/",
					Pcomm:      "sh",
					Exepath:    exepath,
					Comm:       "nslookup",
					Nameserver: "127.0.0.1",
					PktType:    "OUTGOING",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Protocol:   "UDP",
					DstPort:    53,
				},
				{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						CommonData: eventtypes.CommonData{
							Runtime: eventtypes.BasicRuntimeMetadata{
								RuntimeName:   eventtypes.String2RuntimeName(*runtime),
								ContainerName: cn,
							},
						},
					},
					Qr:         dnsTypes.DNSPktTypeResponse,
					Cwd:        "/",
					Pcomm:      "sh",
					Exepath:    exepath,
					Comm:       "nslookup",
					Nameserver: "127.0.0.1",
					PktType:    "HOST",
					DNSName:    "fake.test.com.",
					QType:      "AAAA",
					Rcode:      "No Error",
					Latency:    1,
					NumAnswers: 1,
					Addresses:  []string{"::1"},
					Protocol:   "UDP",
					SrcPort:    53,
				},
			}

			normalize := func(e *dnsTypes.Event) {
				e.ID = ""
				e.Timestamp = 0
				e.MountNsID = 0
				e.NetNsID = 0
				e.Ppid = 0
				e.Pid = 0
				e.Tid = 0

				// Latency should be > 0 only for DNS responses.
				if e.Latency > 0 {
					e.Latency = 1
				}

				e.Runtime.ContainerID = ""
				e.Runtime.ContainerPID = 0
				e.Runtime.ContainerStartedAt = 0
				// TODO: Handle once we support getting ContainerImageName from Docker
				e.Runtime.ContainerImageName = ""
				e.Runtime.ContainerImageDigest = ""

				e.SrcIP = ""
				e.DstIP = ""
				if e.Qr == dnsTypes.DNSPktTypeResponse {
					e.DstPort = 0
				} else {
					e.SrcPort = 0
				}
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	}

	dnsCmds := []string{
		fmt.Sprintf("/dnstester %s & sleep 2", dnsServerArgs), // wait to ensure dns server is running
		"nslookup -type=a fake.test.com. 127.0.0.1",
		"nslookup -type=aaaa fake.test.com. 127.0.0.1",
		"sleep 2", // give time to the tracer to capture events before the container is done
	}

	testSteps := []TestStep{
		traceDNSCmd,
		SleepForSecondsCommand(2), // wait to ensure ig has started
		containerFactory.NewContainer(cn, strings.Join(dnsCmds, " ; "), containers.WithContainerImage(*dnsTesterImage)),
	}

	return testSteps
}

func TestTraceDns(t *testing.T) {
	t.Parallel()
	cn := "test-trace-dns"

	testSteps := newTraceDnsSteps(cn, "")
	RunTestSteps(testSteps, t)
}

func TestTraceDnsUncompress(t *testing.T) {
	t.Parallel()
	cn := "test-trace-dns-uncompress"

	testSteps := newTraceDnsSteps(cn, "-uncompress")
	RunTestSteps(testSteps, t)
}
