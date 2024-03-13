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
	"flag"
	"log"

	"github.com/miekg/dns"
)

var uncompress = flag.Bool("uncompress", false, "Uncompress DNS messages")

func main() {
	flag.Parse()
	log.Printf("Starting dns server with uncompress=%v\n", *uncompress)

	dns.Handle(".", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.Compress = !*uncompress
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

	}))

	server := &dns.Server{Addr: ":53", Net: "udp"}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start dns server %s\n", err)
	}
	defer server.Shutdown()
}
