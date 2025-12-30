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
	"encoding/binary"
	"net"
	"testing"
	"time"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestTraceDns(t *testing.T) {
	paramValues := map[string]string{
		"operator.oci.ebpf.paths": "true",
	}
	gadgettesting.DummyGadgetTest(t, "trace_dns", gadgettesting.WithParamValues(paramValues))
}

type traceDNSEvent struct {
	Src utils.L4Endpoint `json:"src"`
	Dst utils.L4Endpoint `json:"dst"`

	Qr        string `json:"qr"`
	Qtype     string `json:"qtype"`
	QtypeRaw  uint16 `json:"qtype_raw"`
	Name      string `json:"name"`
	Addresses string `json:"addresses"`
}

func TestTraceDnsAAAAIPv6Response(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	const domain = "aaaa.test.local."

	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
	serverConn, err := net.ListenUDP("udp4", serverAddr)
	if err != nil {
		t.Skipf("unable to bind UDP %s: %v", serverAddr.String(), err)
	}
	t.Cleanup(func() { _ = serverConn.Close() })

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		buf := make([]byte, 2048)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		var parser dnsmessage.Parser
		hdr, err := parser.Start(buf)
		if err != nil {
			return
		}
		q, err := parser.Question()
		if err != nil {
			return
		}

		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 hdr.ID,
				Response:           true,
				RecursionDesired:   hdr.RecursionDesired,
				RecursionAvailable: true,
				RCode:              dnsmessage.RCodeSuccess,
			},
			Questions: []dnsmessage.Question{q},
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
						TTL:   10,
					},
					Body: &dnsmessage.AAAAResource{
						AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
					},
				},
			},
		}

		b, err := resp.Pack()
		if err != nil {
			return
		}
		_, _ = serverConn.WriteToUDP(b, clientAddr)
	}()

	paramValues := map[string]string{
		"operator.oci.ebpf.paths": "true",
	}

	runner := gadgetrunner.NewGadgetRunner[traceDNSEvent](t, gadgetrunner.GadgetRunnerOpts[traceDNSEvent]{
		Image:       "trace_dns",
		Timeout:     5 * time.Second,
		ParamValues: paramValues,
		OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
			defer gadgetCtx.Cancel()

			clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer clientConn.Close()

			qname, err := dnsmessage.NewName(domain)
			require.NoError(t, err)

			query := dnsmessage.Message{
				Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
				Questions: []dnsmessage.Question{{
					Name:  qname,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				}},
			}

			qb, err := query.Pack()
			require.NoError(t, err)

			for i := 0; i < 3; i++ {
				_, _ = clientConn.WriteToUDP(qb, serverAddr)
				clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				buf := make([]byte, 2048)
				_, _, _ = clientConn.ReadFromUDP(buf)
				time.Sleep(50 * time.Millisecond)
			}

			time.Sleep(200 * time.Millisecond)
			return nil
		},
	})

	runner.RunGadget()

	require.NotEmpty(t, runner.CapturedEvents)

	var sawQuery, sawResponse bool
	for _, e := range runner.CapturedEvents {
		if e.Qtype == "AAAA" && e.Src.Proto == "UDP" && e.Dst.Proto == "UDP" {
			if e.Qr == "Q" && e.Name == domain {
				sawQuery = true
			}
			if e.Qr == "R" && e.Name == domain && e.Addresses == "::1" {
				sawResponse = true
			}
		}
	}

	require.True(t, sawQuery, "expected AAAA query event")
	require.True(t, sawResponse, "expected AAAA response with ::1")

	<-serverDone
}

func TestTraceDnsUncompressedDNSMessage(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	const name = "uncompressed.test.local."

	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
	serverConn, err := net.ListenUDP("udp4", serverAddr)
	if err != nil {
		t.Skipf("unable to bind UDP %s: %v", serverAddr.String(), err)
	}
	t.Cleanup(func() { _ = serverConn.Close() })

	queryID := uint16(0xBEEF)
	queryBytes := buildUncompressedDNSQuery(queryID, name, uint16(dnsmessage.TypeA))
	responseBytes := buildUncompressedDNSResponseA(queryID, name, net.IPv4(127, 0, 0, 1))

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		buf := make([]byte, 2048)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		_, _ = serverConn.WriteToUDP(responseBytes, clientAddr)
	}()

	paramValues := map[string]string{
		"operator.oci.ebpf.paths": "true",
	}

	runner := gadgetrunner.NewGadgetRunner[traceDNSEvent](t, gadgetrunner.GadgetRunnerOpts[traceDNSEvent]{
		Image:       "trace_dns",
		Timeout:     5 * time.Second,
		ParamValues: paramValues,
		OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
			defer gadgetCtx.Cancel()

			clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer clientConn.Close()

			for i := 0; i < 3; i++ {
				_, _ = clientConn.WriteToUDP(queryBytes, serverAddr)
				clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				buf := make([]byte, 2048)
				_, _, _ = clientConn.ReadFromUDP(buf)
				time.Sleep(50 * time.Millisecond)
			}

			time.Sleep(200 * time.Millisecond)
			return nil
		},
	})

	runner.RunGadget()

	require.NotEmpty(t, runner.CapturedEvents)

	var sawQuery, sawResponse bool
	for _, e := range runner.CapturedEvents {
		if e.Qtype == "A" && e.Src.Proto == "UDP" && e.Dst.Proto == "UDP" {
			if e.Qr == "Q" && e.Name == name {
				sawQuery = true
			}
			if e.Qr == "R" && e.Name == name && e.Addresses == "127.0.0.1" {
				sawResponse = true
			}
		}
	}

	require.True(t, sawQuery, "expected uncompressed A query")
	require.True(t, sawResponse, "expected uncompressed A response")

	<-serverDone
}

func encodeUncompressedQName(name string) []byte {
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if name == "" {
		return []byte{0}
	}

	labels := make([]byte, 0, len(name)+2)
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			lab := name[start:i]
			labels = append(labels, byte(len(lab)))
			labels = append(labels, []byte(lab)...)
			start = i + 1
		}
	}
	return append(labels, 0)
}

func buildUncompressedDNSQuery(id uint16, name string, qtype uint16) []byte {
	qname := encodeUncompressedQName(name)
	b := make([]byte, 12+len(qname)+4)

	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 1)

	copy(b[12:], qname)
	off := 12 + len(qname)

	binary.BigEndian.PutUint16(b[off:off+2], qtype)
	binary.BigEndian.PutUint16(b[off+2:off+4], 1)

	return b
}

func buildUncompressedDNSResponseA(id uint16, name string, ipv4 net.IP) []byte {
	ipv4 = ipv4.To4()
	if ipv4 == nil {
		ipv4 = net.IPv4(127, 0, 0, 1)
	}

	qname := encodeUncompressedQName(name)
	b := make([]byte, 0, 12+(len(qname)+4)+(len(qname)+10+4))

	b = append(b, make([]byte, 12)...)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x8180)
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint16(b[6:8], 1)

	b = append(b, qname...)
	b = append(b, 0, 1, 0, 1)

	b = append(b, qname...)
	b = append(b, 0, 1, 0, 1)
	b = append(b, 0, 0, 0, 10)
	b = append(b, 0, 4)
	b = append(b, ipv4...)

	return b
}
