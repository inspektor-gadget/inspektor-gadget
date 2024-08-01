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
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// Taken from
// https://cs.opensource.google/go/x/net/+/refs/tags/v0.27.0:dns/dnsmessage/message.go
// to trim Type and Rcode prefixes.
// More information about the DNS message format can be found in
// https://datatracker.ietf.org/doc/html/rfc1035 and
// https://datatracker.ietf.org/doc/html/rfc3596.

// A Type is a type of DNS request and response.
type Type uint16

const (
	// ResourceHeader.Type and Question.Type
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41

	// Question.Type
	TypeWKS   Type = 11
	TypeHINFO Type = 13
	TypeMINFO Type = 14
	TypeAXFR  Type = 252
	TypeALL   Type = 255
)

var typeNames = map[Type]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
	TypeOPT:   "OPT",
	TypeWKS:   "WKS",
	TypeHINFO: "HINFO",
	TypeMINFO: "MINFO",
	TypeAXFR:  "AXFR",
	TypeALL:   "ALL",
}

// String implements fmt.Stringer.String.
func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("%d", t)
}

// An RCode is a DNS response status code.
type RCode uint16

// Header.RCode values.
const (
	RCodeSuccess        RCode = 0 // NoError
	RCodeFormatError    RCode = 1 // FormErr
	RCodeServerFailure  RCode = 2 // ServFail
	RCodeNameError      RCode = 3 // NXDomain
	RCodeNotImplemented RCode = 4 // NotImp
	RCodeRefused        RCode = 5 // Refused
)

var rCodeNames = map[RCode]string{
	RCodeSuccess:        "Success",
	RCodeFormatError:    "FormatError",
	RCodeServerFailure:  "ServerFailure",
	RCodeNameError:      "NameError",
	RCodeNotImplemented: "NotImplemented",
	RCodeRefused:        "Refused",
}

// String implements fmt.Stringer.String.
func (r RCode) String() string {
	if n, ok := rCodeNames[r]; ok {
		return n
	}
	return fmt.Sprintf("%d", r)
}

//export gadgetInit
func gadgetInit() int {
	ds, err := api.GetDataSource("dns")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	dataF, err := ds.GetField("data")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	lenF, err := ds.GetField("data_len")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	dnsOffF, err := ds.GetField("dns_off")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	idF, err := ds.AddField("id", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	qrRawF, err := ds.AddField("qr_raw", api.Kind_Bool)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	qrF, err := ds.AddField("qr", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	qtypeRawF, err := ds.AddField("qtype_raw", api.Kind_Uint16)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	qtypeF, err := ds.AddField("qtype", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	nameF, err := ds.AddField("name", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	rcodeRawF, err := ds.AddField("rcode_raw", api.Kind_Uint16)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	rcodeF, err := ds.AddField("rcode", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	numAnswersF, err := ds.AddField("num_answers", api.Kind_Int32)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	addressesF, err := ds.AddField("addresses", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		// Get all fields sent by ebpf
		payloadLen, err := lenF.Uint32(data)
		if err != nil {
			api.Warnf("failed to get data_len: %s", err)
			return
		}
		dnsOff, err := dnsOffF.Uint16(data)
		if err != nil {
			api.Warnf("failed to get dns_off: %s", err)
			return
		}

		if payloadLen < uint32(dnsOff) {
			api.Warnf("packet too short: dataLen: %d < dnsOff: %d", payloadLen, dnsOff)
			return
		}

		payload, err := dataF.Bytes(data)
		if err != nil {
			api.Warnf("failed to get data: %s", err)
			return
		}

		msg := dnsmessage.Message{}
		if err := msg.Unpack(payload[dnsOff:]); err != nil {
			api.Warnf("failed to unpack dns message: %s", err)
			return
		}

		idF.SetString(data, fmt.Sprintf("%.4x", msg.ID))

		qrRawF.SetBool(data, msg.Header.Response)
		if msg.Header.Response {
			rcodeRawF.SetUint16(data, uint16(msg.Header.RCode))
			rcodeF.SetString(data, RCode(msg.Header.RCode).String())
			qrF.SetString(data, "R")
		} else {
			qrF.SetString(data, "Q")
		}

		if len(msg.Questions) > 0 {
			question := msg.Questions[0]
			qtypeRawF.SetUint16(data, uint16(question.Type))
			qtypeF.SetString(data, Type(question.Type).String())
			nameF.SetString(data, question.Name.String())
		}

		numAnswersF.SetInt32(data, int32(len(msg.Answers)))

		var addresses []string

		for _, answer := range msg.Answers {
			var str string
			switch answer.Header.Type {
			case dnsmessage.TypeA:
				ipv4 := answer.Body.(*dnsmessage.AResource)
				str = net.IP(ipv4.A[:]).String()
			case dnsmessage.TypeAAAA:
				ipv6 := answer.Body.(*dnsmessage.AAAAResource)
				str = net.IP(ipv6.AAAA[:]).String()
			}

			addresses = append(addresses, str)
		}

		addressesF.SetString(data, strings.Join(addresses, ","))

	}, 0)

	return 0
}

func main() {}
