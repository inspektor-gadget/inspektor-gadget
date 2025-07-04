package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	listenAddr   = "0.0.0.0:5353"   // change to ":53" if running as root
	targetDomain = "fake.test.com." // with trailing dot (FQDN)
	responseIP   = "1.2.3.4"
	numWorkers   = 50
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  server")
		fmt.Println("  client <dns-server:port> [max-requests-per-second]")
		os.Exit(1)
	}

	if runtime.GOMAXPROCS(0) < numWorkers {
		runtime.GOMAXPROCS(numWorkers) // ensure enough OS threads
	}

	switch os.Args[1] {
	case "server":
		if err := doServer(); err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
		return
	case "client":
		if len(os.Args) < 3 {
			fmt.Println("Usage: client <dns-server:port> [max-requests-per-second]")
			os.Exit(1)
		}

		var maxRPS int
		if len(os.Args) >= 4 {
			var err error
			maxRPS, err = strconv.Atoi(os.Args[3])
			if err != nil {
				log.Fatalf("Invalid max-requests-per-second value: %v", err)
			}
		}

		if err := doClient(maxRPS); err != nil {
			log.Fatalf("Failed to start DNS client: %v", err)
		}
		return
	default:
		fmt.Println("Invalid argument. Use 'server' or 'client'.")
		os.Exit(1)
	}
}

func doServer() error {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to UDP %s: %w", listenAddr, err)
	}
	log.Printf("DNS server listening on %s (UDP) with %d goroutines\n", listenAddr, numWorkers)

	for i := 0; i < numWorkers; i++ {
		go serveDNS(pc)
	}

	select {} // block forever
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

func doClient(maxRPS int) error {
	server := os.Args[2]

	var counter uint64

	// Print stats every second
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for range ticker.C {
			count := atomic.SwapUint64(&counter, 0)
			fmt.Printf("Requests per second: %d\n", count)
		}
	}()

	// Create rate limiter if maxRPS is specified
	var rateLimiter *time.Ticker
	if maxRPS > 0 {
		interval := time.Second / time.Duration(maxRPS)
		rateLimiter = time.NewTicker(interval)
		defer rateLimiter.Stop()
		fmt.Printf("Rate limiting enabled: max %d requests per second\n", maxRPS)
	}

	// Use multiple goroutines to send more DNS requests
	for i := 0; i < numWorkers; i++ {
		go func() {
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(targetDomain), dns.TypeA)

			for {
				// Wait for rate limiter if enabled
				if rateLimiter != nil {
					<-rateLimiter.C
				}

				_, _, err := c.ExchangeContext(context.Background(), m, server)
				if err == nil {
					atomic.AddUint64(&counter, 1)
				}
			}
		}()
	}

	select {} // Block forever
}
