package main

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

const (
	listenAddr   = "0.0.0.0:5353"
	targetDomain = "fake.test.com."
	responseIP   = "1.2.3.4"
	numWorkers   = 50
)

type dnsServer struct {
}

func NewDNSServer(_ string) (Generator, error) {
	return &dnsServer{}, nil
}

func (s *dnsServer) Start() error {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to UDP %s: %w", listenAddr, err)
	}

	fmt.Printf("DNS server listening on %s (UDP) with %d goroutines\n", listenAddr, numWorkers)

	for range numWorkers {
		go serveDNS(pc)
	}
	return nil
}

func (s *dnsServer) Stop() error {
	return nil
}

func serveDNS(conn net.PacketConn) {
	buffer := make([]byte, 512) // typical DNS packet size

	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("ReadFrom error: %v", err)
			continue
		}

		// Copy buffer since it's reused
		reqBuf := make([]byte, n)
		copy(reqBuf, buffer[:n])

		go handleRequest(conn, addr, reqBuf)
	}
}

func handleRequest(conn net.PacketConn, addr net.Addr, data []byte) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return
	}

	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true

	for _, q := range msg.Question {
		if q.Name == targetDomain && q.Qtype == dns.TypeA {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				A: net.ParseIP(responseIP),
			}
			resp.Answer = append(resp.Answer, rr)
		}
	}

	respBytes, err := resp.Pack()
	if err != nil {
		return
	}

	conn.WriteTo(respBytes, addr)
}

func init() {
	// Register the DNS server generator
	RegisterGenerator("dns-server", NewDNSServer)
}
