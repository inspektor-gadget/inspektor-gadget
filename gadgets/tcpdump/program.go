// Copyright 2024 The Inspektor Gadget authors
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

	"github.com/ghedo/go.pkt/layers"
	"github.com/ghedo/go.pkt/packet"
	"github.com/ghedo/go.pkt/packet/arp"
	"github.com/ghedo/go.pkt/packet/eth"
	"github.com/ghedo/go.pkt/packet/icmpv4"
	"github.com/ghedo/go.pkt/packet/icmpv6"
	"github.com/ghedo/go.pkt/packet/ipv4"
	"github.com/ghedo/go.pkt/packet/ipv6"
	"github.com/ghedo/go.pkt/packet/tcp"
	"github.com/ghedo/go.pkt/packet/udp"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// TODO: which fields to show / hide
// TODO: add missing protocols
func layerToString(pkt packet.Packet) string {
	switch pkt.GetType() {
	case packet.ARP:
		arp := pkt.(*arp.Packet)
		return fmt.Sprintf("arp(op=%s, hwsrc=%s, hwdst=%s)",
			arp.Operation.String(), arp.HWSrcAddr.String(), arp.HWDstAddr.String())
	case packet.Eth:
		eth := pkt.(*eth.Packet)
		return fmt.Sprintf("ethernet(dst=%s, src=%s, type=%s)",
			eth.DstAddr.String(), eth.SrcAddr.String(), eth.Type.String())
	case packet.IPv4:
		ipv4 := pkt.(*ipv4.Packet)
		return fmt.Sprintf("ipv4(src=%s, dst=%s, proto=%s)",
			ipv4.SrcAddr.String(), ipv4.DstAddr.String(), ipv4.Protocol.String())
	case packet.IPv6:
		ipv6 := pkt.(*ipv6.Packet)
		return fmt.Sprintf("ipv6(src=%s, dst=%s, proto=%s)",
			ipv6.SrcAddr.String(), ipv6.DstAddr.String(), ipv6.NextHdr.String())
	case packet.TCP:
		tcp := pkt.(*tcp.Packet)
		return fmt.Sprintf("tcp(src=%d, dst=%d)", tcp.SrcPort, tcp.DstPort)
	case packet.UDP:
		udp := pkt.(*udp.Packet)
		return fmt.Sprintf("udp(src=%d, dst=%d)", udp.SrcPort, udp.DstPort)
	case packet.ICMPv4:
		icmpv4 := pkt.(*icmpv4.Packet)
		return fmt.Sprintf("icmpv4(type=%d, code=%d)", icmpv4.Type, icmpv4.Code)
	case packet.ICMPv6:
		icmpv6 := pkt.(*icmpv6.Packet)
		return fmt.Sprintf("icmpv6(type=%d, code=%d)", icmpv6.Type, icmpv6.Code)
	default:
		return fmt.Sprintf("(%s len=%d)",
			pkt.GetType().String(), pkt.GetLength())
	}
}

//export init
func gadgetInit() int {
	ds, err := api.GetDataSource("tcpdump")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	dataF, err := ds.GetField("data")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	lenF, err := ds.GetField("len")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	prettyF, err := ds.AddField("pretty", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		// Get all fields sent by ebpf
		payload, _ := dataF.Bytes(data)
		payloadLen, _ := lenF.Uint32(data)

		_ = payload
		_ = payloadLen

		//	api.Infof("payload len is: %d\n", payloadLen)

		// Assume Ethernet as datalink layer
		pkt, err := layers.UnpackAll(payload, packet.Eth)
		if err != nil {
			api.Warnf("failed to unpack packet: %s", err)
			return
		}

		// We cant' use pkt.String() because it panics in wasm
		// Hence, do it manually
		var str string

		for {
			str += layerToString(pkt)
			pkt = pkt.Payload()
			if pkt == nil {
				break
			}
			str += " | "
		}

		prettyF.SetString(data, str)

	}, 0)

	return 0
}

func main() {}
