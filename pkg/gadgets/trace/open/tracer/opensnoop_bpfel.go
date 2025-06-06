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

type opensnoopEvent struct {
	_         structs.HostLayout
	Timestamp uint64
	Pid       uint32
	Tid       uint32
	Uid       uint32
	Gid       uint32
	MntnsId   uint64
	Err       int32
	Fd        uint32
	Flags     int32
	Mode      uint16
	Comm      [16]uint8
	Fname     [255]uint8
	FullFname [512]uint8
	_         [3]byte
}

type opensnoopPrefixKey struct {
	_         structs.HostLayout
	Prefixlen uint32
	Filename  [255]uint8
	_         [1]byte
}

// loadOpensnoop returns the embedded CollectionSpec for opensnoop.
func loadOpensnoop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_OpensnoopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load opensnoop: %w", err)
	}

	return spec, err
}

// loadOpensnoopObjects loads opensnoop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*opensnoopObjects
//	*opensnoopPrograms
//	*opensnoopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadOpensnoopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadOpensnoop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// opensnoopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopSpecs struct {
	opensnoopProgramSpecs
	opensnoopMapSpecs
	opensnoopVariableSpecs
}

// opensnoopProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopProgramSpecs struct {
	IgOpenE   *ebpf.ProgramSpec `ebpf:"ig_open_e"`
	IgOpenX   *ebpf.ProgramSpec `ebpf:"ig_open_x"`
	IgOpenatE *ebpf.ProgramSpec `ebpf:"ig_openat_e"`
	IgOpenatX *ebpf.ProgramSpec `ebpf:"ig_openat_x"`
}

// opensnoopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopMapSpecs struct {
	Bufs                 *ebpf.MapSpec `ebpf:"bufs"`
	EmptyEvent           *ebpf.MapSpec `ebpf:"empty_event"`
	Events               *ebpf.MapSpec `ebpf:"events"`
	GadgetMntnsFilterMap *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
	PrefixKeys           *ebpf.MapSpec `ebpf:"prefix_keys"`
	Prefixes             *ebpf.MapSpec `ebpf:"prefixes"`
	Start                *ebpf.MapSpec `ebpf:"start"`
}

// opensnoopVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopVariableSpecs struct {
	GadgetFilterByMntns *ebpf.VariableSpec `ebpf:"gadget_filter_by_mntns"`
	GetFullPath         *ebpf.VariableSpec `ebpf:"get_full_path"`
	PrefixesNr          *ebpf.VariableSpec `ebpf:"prefixes_nr"`
	TargFailed          *ebpf.VariableSpec `ebpf:"targ_failed"`
	TargPid             *ebpf.VariableSpec `ebpf:"targ_pid"`
	TargTgid            *ebpf.VariableSpec `ebpf:"targ_tgid"`
	TargUid             *ebpf.VariableSpec `ebpf:"targ_uid"`
	Unusedevent         *ebpf.VariableSpec `ebpf:"unusedevent"`
}

// opensnoopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopObjects struct {
	opensnoopPrograms
	opensnoopMaps
	opensnoopVariables
}

func (o *opensnoopObjects) Close() error {
	return _OpensnoopClose(
		&o.opensnoopPrograms,
		&o.opensnoopMaps,
	)
}

// opensnoopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopMaps struct {
	Bufs                 *ebpf.Map `ebpf:"bufs"`
	EmptyEvent           *ebpf.Map `ebpf:"empty_event"`
	Events               *ebpf.Map `ebpf:"events"`
	GadgetMntnsFilterMap *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
	PrefixKeys           *ebpf.Map `ebpf:"prefix_keys"`
	Prefixes             *ebpf.Map `ebpf:"prefixes"`
	Start                *ebpf.Map `ebpf:"start"`
}

func (m *opensnoopMaps) Close() error {
	return _OpensnoopClose(
		m.Bufs,
		m.EmptyEvent,
		m.Events,
		m.GadgetMntnsFilterMap,
		m.PrefixKeys,
		m.Prefixes,
		m.Start,
	)
}

// opensnoopVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopVariables struct {
	GadgetFilterByMntns *ebpf.Variable `ebpf:"gadget_filter_by_mntns"`
	GetFullPath         *ebpf.Variable `ebpf:"get_full_path"`
	PrefixesNr          *ebpf.Variable `ebpf:"prefixes_nr"`
	TargFailed          *ebpf.Variable `ebpf:"targ_failed"`
	TargPid             *ebpf.Variable `ebpf:"targ_pid"`
	TargTgid            *ebpf.Variable `ebpf:"targ_tgid"`
	TargUid             *ebpf.Variable `ebpf:"targ_uid"`
	Unusedevent         *ebpf.Variable `ebpf:"unusedevent"`
}

// opensnoopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopPrograms struct {
	IgOpenE   *ebpf.Program `ebpf:"ig_open_e"`
	IgOpenX   *ebpf.Program `ebpf:"ig_open_x"`
	IgOpenatE *ebpf.Program `ebpf:"ig_openat_e"`
	IgOpenatX *ebpf.Program `ebpf:"ig_openat_x"`
}

func (p *opensnoopPrograms) Close() error {
	return _OpensnoopClose(
		p.IgOpenE,
		p.IgOpenX,
		p.IgOpenatE,
		p.IgOpenatX,
	)
}

func _OpensnoopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed opensnoop_bpfel.o
var _OpensnoopBytes []byte
