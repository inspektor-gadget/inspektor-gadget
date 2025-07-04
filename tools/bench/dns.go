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
