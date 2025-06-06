// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64 || wasm

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"structs"

	"github.com/cilium/ebpf"
)

type dnsEventT struct {
	_         structs.HostLayout
	Netns     uint32
	_         [4]byte
	Timestamp uint64
	MountNsId uint64
	Pid       uint32
	Tid       uint32
	Ppid      uint32
	Uid       uint32
	Gid       uint32
	Comm      [16]uint8
	Pcomm     [16]uint8
	SaddrV6   [16]uint8
	DaddrV6   [16]uint8
	Af        uint16
	Sport     uint16
	Dport     uint16
	DnsOff    uint16
	Proto     uint8
	PktType   uint8
	_         [2]byte
	LatencyNs uint64
}

type dnsQueryKeyT struct {
	_       structs.HostLayout
	PidTgid uint64
	Id      uint16
	Pad     [3]uint16
}

type dnsSocketsKey struct {
	_      structs.HostLayout
	Netns  uint32
	Family uint16
	Proto  uint8
	_      [1]byte
	Port   uint16
	_      [2]byte
}

type dnsSocketsValue struct {
	_                 structs.HostLayout
	Mntns             uint64
	PidTgid           uint64
	UidGid            uint64
	Task              [16]int8
	Ptask             [16]int8
	Sock              uint64
	DeletionTimestamp uint64
	Cwd               [512]int8
	Exepath           [512]int8
	Ppid              uint32
	Ipv6only          int8
	_                 [3]byte
}

// loadDns returns the embedded CollectionSpec for dns.
func loadDns() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DnsBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load dns: %w", err)
	}

	return spec, err
}

// loadDnsObjects loads dns and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*dnsObjects
//	*dnsPrograms
//	*dnsMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadDnsObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDns()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// dnsSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dnsSpecs struct {
	dnsProgramSpecs
	dnsMapSpecs
	dnsVariableSpecs
}

// dnsProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dnsProgramSpecs struct {
	IgTraceDns *ebpf.ProgramSpec `ebpf:"ig_trace_dns"`
}

// dnsMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dnsMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	GadgetSockets *ebpf.MapSpec `ebpf:"gadget_sockets"`
	QueryMap      *ebpf.MapSpec `ebpf:"query_map"`
	TmpEvents     *ebpf.MapSpec `ebpf:"tmp_events"`
}

// dnsVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dnsVariableSpecs struct {
	Ports       *ebpf.VariableSpec `ebpf:"ports"`
	PortsLen    *ebpf.VariableSpec `ebpf:"ports_len"`
	Unusedevent *ebpf.VariableSpec `ebpf:"unusedevent"`
}

// dnsObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadDnsObjects or ebpf.CollectionSpec.LoadAndAssign.
type dnsObjects struct {
	dnsPrograms
	dnsMaps
	dnsVariables
}

func (o *dnsObjects) Close() error {
	return _DnsClose(
		&o.dnsPrograms,
		&o.dnsMaps,
	)
}

// dnsMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadDnsObjects or ebpf.CollectionSpec.LoadAndAssign.
type dnsMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	GadgetSockets *ebpf.Map `ebpf:"gadget_sockets"`
	QueryMap      *ebpf.Map `ebpf:"query_map"`
	TmpEvents     *ebpf.Map `ebpf:"tmp_events"`
}

func (m *dnsMaps) Close() error {
	return _DnsClose(
		m.Events,
		m.GadgetSockets,
		m.QueryMap,
		m.TmpEvents,
	)
}

// dnsVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadDnsObjects or ebpf.CollectionSpec.LoadAndAssign.
type dnsVariables struct {
	Ports       *ebpf.Variable `ebpf:"ports"`
	PortsLen    *ebpf.Variable `ebpf:"ports_len"`
	Unusedevent *ebpf.Variable `ebpf:"unusedevent"`
}

// dnsPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadDnsObjects or ebpf.CollectionSpec.LoadAndAssign.
type dnsPrograms struct {
	IgTraceDns *ebpf.Program `ebpf:"ig_trace_dns"`
}

func (p *dnsPrograms) Close() error {
	return _DnsClose(
		p.IgTraceDns,
	)
}

func _DnsClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed dns_bpfel.o
var _DnsBytes []byte
