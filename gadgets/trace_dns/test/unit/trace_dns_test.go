// Copyright 2025 The Inspektor Gadget authors
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

package tests

import (
	"flag"
	"fmt"
	"log"

	"testing"
	"time"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/miekg/dns"
)

type ExpectedTraceDnsEvent struct { // copied from integration test for now
	Timestamp string        `json:"timestamp"`
	NetNsID   uint64        `json:"netns_id"`
	Proc      utils.Process `json:"proc"`

	Src utils.L4Endpoint `json:"src"`
	Dst utils.L4Endpoint `json:"dst"`

	// Raw fields are coming from wasm, test them too
	ID                 string `json:"id"`
	Qtype              string `json:"qtype"`
	QtypeRaw           uint16 `json:"qtype_raw"`
	PktType            string `json:"pkt_type"`
	RcodeRaw           uint16 `json:"rcode_raw"`
	Rcode              string `json:"rcode"`
	Latency            uint64 `json:"latency_ns_raw"`
	QrRaw              bool   `json:"qr_raw"`
	Qr                 string `json:"qr"`
	Name               string `json:"name"`
	Addresses          string `json:"addresses"`
	Truncated          bool   `json:"tc"`
	RecursionDesired   bool   `json:"rd"`
	RecursionAvailable bool   `json:"ra"`
}

type testDef struct {
	name         string
	runnerConfig *utilstest.RunnerConfig
}

func printEvents(t *testing.T, events []ExpectedTraceDnsEvent) {
	fmt.Printf("Printing %d events:\n", len(events))
	for _, event := range events {
		fmt.Printf("Event: \n")
		fmt.Printf("  Timestamp: %s\n", event.Timestamp)
		fmt.Printf("  NetNsID: %d\n", event.NetNsID)
		fmt.Printf("  Proc: %v\n", event.Proc)
		fmt.Printf("  Src: %v\n", event.Src)
		fmt.Printf("  Dst: %v\n", event.Dst)
		fmt.Printf("  ID: %s\n", event.ID)
		fmt.Printf("  Qtype: %s\n", event.Qtype)
		fmt.Printf("  QtypeRaw: %d\n", event.QtypeRaw)
		fmt.Printf("  PktType: %s\n", event.PktType)
		fmt.Printf("  RcodeRaw: %d\n", event.RcodeRaw)
		fmt.Printf("  Rcode: %s\n", event.Rcode)
		fmt.Printf("  Latency: %d\n", event.Latency)
		fmt.Printf("  QrRaw: %t\n", event.QrRaw)
		fmt.Printf("  Qr: %s\n", event.Qr)
		fmt.Printf("  Name: %s\n", event.Name)
		fmt.Printf("  Addresses: %s\n", event.Addresses)
		fmt.Printf("  Truncated: %t\n", event.Truncated)
		fmt.Printf("  RecursionDesired: %t\n", event.RecursionDesired)
		fmt.Printf("  RecursionAvailable: %t\n", event.RecursionAvailable)
	}
}

func TestTraceDnsGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := []testDef{
		{
			name: "basic",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tcpSrv := &dns.Server{
				Addr: "127.0.0.1:53",
				Net:  "tcp",
			}

			tcpSrv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				m := new(dns.Msg)
				m.Compress = !*flag.Bool("uncompress", false, "Uncompress DNS messages")
				m.SetReply(r)

				var rr dns.RR
				var err error
				if r.Question[0].Name == "fake.test.com." {
					switch r.Question[0].Qtype {
					case dns.TypeA:
						rr, err = dns.NewRR("fake.test.com. A 127.0.0.1")
					case dns.TypeAAAA:
						rr, err = dns.NewRR("fake.test.com. AAAA ::1")
					}
					if err != nil {
						log.Fatalf("Failed to create RR %s\n", err)
					}
					m.Answer = append(m.Answer, rr)
				} else {
					m.SetRcode(r, dns.RcodeNameError)
				}

				if err = w.WriteMsg(m); err != nil {
					log.Fatalf("Failed to write msg %s\n", err)
				}

			})

			go tcpSrv.ListenAndServe()
			defer tcpSrv.Shutdown()

			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			onGadgetRun := func(gctx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					client := &dns.Client{Net: "tcp"}
					msg := new(dns.Msg)
					msg.SetQuestion("fake.test.com", dns.TypeA)

					resp, _, err := client.Exchange(msg, tcpSrv.Addr)
					if err != nil {
						return fmt.Errorf("dns query failed: %w", err)
					}
					fmt.Printf("got response: %v\n", resp)
					return nil
				})
				return nil
			}

			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceDnsEvent]{
				Image:          "trace_dns",
				Timeout:        5 * time.Second,
				MntnsFilterMap: nil,
				OnGadgetRun:    onGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
			gadgetRunner.RunGadget()

			printEvents(t, gadgetRunner.CapturedEvents)

		})
	}
}
