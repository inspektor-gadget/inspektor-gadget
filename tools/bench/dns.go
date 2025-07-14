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

package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type dnsClientGenerator struct {
	baseGenerator

	c *dns.Client
	m *dns.Msg
}

type dnsClientConf struct {
	server string
	maxRPS int
}

func NewDNSClient(confStr string) (Generator, error) {
	conf, err := parseConfStr(confStr)
	if err != nil {
		return nil, fmt.Errorf("parsing DNS client config: %w", err)
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(targetDomain), dns.TypeA)

	cb := func() error {
		_, _, err := c.Exchange(m, conf.server)
		return err

	}

	g := &dnsClientGenerator{
		baseGenerator: NewBaseGen(cb),
		c:             c,
		m:             m,
	}

	return g, nil
}

func parseConfStr(confStr string) (*dnsClientConf, error) {
	dnsClientConf := dnsClientConf{
		maxRPS: eventsPerSecond,
	}

	parts := strings.Split(confStr, ";")

	for _, part := range parts {
		confParts := strings.SplitN(part, "=", 2)
		confName := confParts[0]
		confVal := confParts[1]

		switch confName {
		case "server":
			dnsClientConf.server = confVal
		}
	}
	return &dnsClientConf, nil
}

func init() {
	RegisterGenerator("dns", NewDNSClient)
}
