// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tcpconnlatEvent struct {
	SaddrV6   [16]uint8
	DaddrV6   [16]uint8
	Comm      [16]uint8
	Timestamp uint64
	MntnsId   uint64
	Delta     uint64
	Tgid      uint32
	Pid       uint32
	Af        int32
	Lport     uint16
	Dport     uint16
}

type tcpconnlatPiddata struct {
	Comm    [16]int8
	Ts      uint64
	Tgid    uint32
	Pid     uint32
	MntnsId uint64
}

// loadTcpconnlat returns the embedded CollectionSpec for tcpconnlat.
func loadTcpconnlat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TcpconnlatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tcpconnlat: %w", err)
	}

	return spec, err
}

// loadTcpconnlatObjects loads tcpconnlat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tcpconnlatObjects
//	*tcpconnlatPrograms
//	*tcpconnlatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTcpconnlatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTcpconnlat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tcpconnlatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnlatSpecs struct {
	tcpconnlatProgramSpecs
	tcpconnlatMapSpecs
}

// tcpconnlatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnlatProgramSpecs struct {
	IgTcp4Destroy *ebpf.ProgramSpec `ebpf:"ig_tcp4_destroy"`
	IgTcp6Destroy *ebpf.ProgramSpec `ebpf:"ig_tcp6_destroy"`
	IgTcpRsp      *ebpf.ProgramSpec `ebpf:"ig_tcp_rsp"`
	IgTcpcV4CoE   *ebpf.ProgramSpec `ebpf:"ig_tcpc_v4_co_e"`
	IgTcpcV6CoE   *ebpf.ProgramSpec `ebpf:"ig_tcpc_v6_co_e"`
}

// tcpconnlatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnlatMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	MountNsFilter *ebpf.MapSpec `ebpf:"mount_ns_filter"`
	Start         *ebpf.MapSpec `ebpf:"start"`
}

// tcpconnlatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnlatObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnlatObjects struct {
	tcpconnlatPrograms
	tcpconnlatMaps
}

func (o *tcpconnlatObjects) Close() error {
	return _TcpconnlatClose(
		&o.tcpconnlatPrograms,
		&o.tcpconnlatMaps,
	)
}

// tcpconnlatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnlatObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnlatMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	MountNsFilter *ebpf.Map `ebpf:"mount_ns_filter"`
	Start         *ebpf.Map `ebpf:"start"`
}

func (m *tcpconnlatMaps) Close() error {
	return _TcpconnlatClose(
		m.Events,
		m.MountNsFilter,
		m.Start,
	)
}

// tcpconnlatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnlatObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnlatPrograms struct {
	IgTcp4Destroy *ebpf.Program `ebpf:"ig_tcp4_destroy"`
	IgTcp6Destroy *ebpf.Program `ebpf:"ig_tcp6_destroy"`
	IgTcpRsp      *ebpf.Program `ebpf:"ig_tcp_rsp"`
	IgTcpcV4CoE   *ebpf.Program `ebpf:"ig_tcpc_v4_co_e"`
	IgTcpcV6CoE   *ebpf.Program `ebpf:"ig_tcpc_v6_co_e"`
}

func (p *tcpconnlatPrograms) Close() error {
	return _TcpconnlatClose(
		p.IgTcp4Destroy,
		p.IgTcp6Destroy,
		p.IgTcpRsp,
		p.IgTcpcV4CoE,
		p.IgTcpcV6CoE,
	)
}

func _TcpconnlatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tcpconnlat_bpfel_arm64.o
var _TcpconnlatBytes []byte
