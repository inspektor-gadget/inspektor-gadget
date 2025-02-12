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

package eventgenerator

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/nsenter"
)

const (
	DNSGeneratorType = "dns"
	ParamDomain      = "domain"
	ParamQueryType   = "query-type"
	ParamNameserver  = "nameserver"
	ParamPort        = "port"
)

func NewDNSGenerator() Generator {
	return dnsGenerator{}
}

type dnsGenerator struct{}

func (d dnsGenerator) Generate(container containercollection.Container, params map[string]string) error {
	domain, ok := params[ParamDomain]
	if !ok || domain == "" {
		return fmt.Errorf("domain parameter is required")
	}
	qt, ok := params[ParamQueryType]
	if !ok || qt == "" {
		qt = "A"
	}
	ns, ok := params[ParamNameserver]
	if !ok || ns == "" {
		servers, _ := nameserverFromResolvConf(int(container.Runtime.ContainerPID))
		if len(servers) == 0 {
			return fmt.Errorf("no nameservers found in container resolv.conf")
		}
		// TODO: support multiple nameservers
		ns = servers[0]
	}
	port, ok := params[ParamPort]
	if !ok || port == "" {
		port = "53"
	}
	ns = fmt.Sprintf("%s:%s", ns, port)

	cb := func() error {
		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(domain, dns.StringToType[qt])
		_, _, err := c.Exchange(m, ns)
		if err != nil {
			return fmt.Errorf("sending query: %w", err)
		}
		return nil
	}

	return nsenter.NetnsEnter(int(container.Runtime.ContainerPID), cb)
}

func (d dnsGenerator) Cleanup() error {
	return nil
}

func nameserverFromResolvConf(containerPid int) ([]string, error) {
	rcPath := fmt.Sprintf("/proc/%d/root/etc/resolv.conf", containerPid)
	rc, err := os.ReadFile(rcPath)
	if err != nil {
		return nil, fmt.Errorf("reading container resolv.conf: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(rc))
	var ns []string
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if s, ok := strings.CutPrefix(line, "nameserver"); ok {
			ns = append(ns, strings.TrimSpace(s))
		}
	}
	if len(ns) == 0 {
		return nil, fmt.Errorf("no nameservers found in resolv.conf")
	}
	return ns, nil
}
