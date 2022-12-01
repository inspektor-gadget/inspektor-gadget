// Copyright 2019-2021 The Inspektor Gadget authors
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

package gadgets

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	PinPath = "/sys/fs/bpf/gadget"

	// The Trace custom resource is preferably in the "gadget" namespace
	TraceDefaultNamespace = "gadget"

	PerfBufferPages = 64
)

// CloseLink closes l if it's not nil and returns nil
func CloseLink(l link.Link) link.Link {
	if l != nil {
		l.Close()
	}
	return nil
}

// DataEnricher is used to enrich events with Kubernetes information,
// like node, namespace, pod name and container name.
type DataEnricher interface {
	Enrich(event *types.CommonData, mountnsid uint64)
}

func FromCString(in []byte) string {
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			return string(in[:i])
		}
	}
	return string(in)
}

func FromCStringN(in []byte, length int) string {
	l := len(in)
	if length < l {
		l = length
	}

	for i := 0; i < l; i++ {
		if in[i] == 0 {
			return string(in[:i])
		}
	}
	return string(in[:l])
}

func Htonl(hl uint32) uint32 {
	var nl [4]byte
	binary.BigEndian.PutUint32(nl[:], hl)
	return *(*uint32)(unsafe.Pointer(&nl[0]))
}

func Htons(hs uint16) uint16 {
	var ns [2]byte
	binary.BigEndian.PutUint16(ns[:], hs)
	return *(*uint16)(unsafe.Pointer(&ns[0]))
}

func IPStringFromBytes(ipBytes [16]byte, ipType int) string {
	switch ipType {
	case 4:
		return netip.AddrFrom4(*(*[4]byte)(ipBytes[0:4])).String()
	case 6:
		return netip.AddrFrom16(ipBytes).String()
	default:
		return ""
	}
}
