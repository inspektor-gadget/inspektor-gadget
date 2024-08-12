// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package uprobetracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadUsdthelper returns the embedded CollectionSpec for usdthelper.
func loadUsdthelper() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_UsdthelperBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load usdthelper: %w", err)
	}

	return spec, err
}

// loadUsdthelperObjects loads usdthelper and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*usdthelperObjects
//	*usdthelperPrograms
//	*usdthelperMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadUsdthelperObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadUsdthelper()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// usdthelperSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type usdthelperSpecs struct {
	usdthelperProgramSpecs
	usdthelperMapSpecs
}

// usdthelperSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type usdthelperProgramSpecs struct {
	UsdtGetArgument *ebpf.ProgramSpec `ebpf:"__usdt_get_argument"`
}

// usdthelperMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type usdthelperMapSpecs struct {
	UsdtArgsBuffer *ebpf.MapSpec `ebpf:"__usdt_args_buffer"`
	UsdtArgsInfo   *ebpf.MapSpec `ebpf:"__usdt_args_info"`
}

// usdthelperObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadUsdthelperObjects or ebpf.CollectionSpec.LoadAndAssign.
type usdthelperObjects struct {
	usdthelperPrograms
	usdthelperMaps
}

func (o *usdthelperObjects) Close() error {
	return _UsdthelperClose(
		&o.usdthelperPrograms,
		&o.usdthelperMaps,
	)
}

// usdthelperMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadUsdthelperObjects or ebpf.CollectionSpec.LoadAndAssign.
type usdthelperMaps struct {
	UsdtArgsBuffer *ebpf.Map `ebpf:"__usdt_args_buffer"`
	UsdtArgsInfo   *ebpf.Map `ebpf:"__usdt_args_info"`
}

func (m *usdthelperMaps) Close() error {
	return _UsdthelperClose(
		m.UsdtArgsBuffer,
		m.UsdtArgsInfo,
	)
}

// usdthelperPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadUsdthelperObjects or ebpf.CollectionSpec.LoadAndAssign.
type usdthelperPrograms struct {
	UsdtGetArgument *ebpf.Program `ebpf:"__usdt_get_argument"`
}

func (p *usdthelperPrograms) Close() error {
	return _UsdthelperClose(
		p.UsdtGetArgument,
	)
}

func _UsdthelperClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed usdthelper_x86_bpfel.o
var _UsdthelperBytes []byte
