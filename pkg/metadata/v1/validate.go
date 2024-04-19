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

package metadatav1

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/hashicorp/go-multierror"
	"gopkg.in/yaml.v2"
)

func ValidateMetadataFile(path string, spec *ebpf.CollectionSpec) error {
	metadataFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening metadata file: %w", err)
	}
	defer metadataFile.Close()

	metadata := &GadgetMetadata{}
	if err := yaml.NewDecoder(metadataFile).Decode(metadata); err != nil {
		return fmt.Errorf("decoding metadata file: %w", err)
	}

	return metadata.Validate(spec)
}

func (m *GadgetMetadata) Validate(spec *ebpf.CollectionSpec) error {
	var result error

	if m.Name == "" {
		result = multierror.Append(result, errors.New("gadget name is required"))
	}

	if err := validateEbpfParams(m, spec); err != nil {
		result = multierror.Append(result, err)
	}

	if err := validateTracers(m, spec); err != nil {
		result = multierror.Append(result, err)
	}

	if err := validateToppers(m, spec); err != nil {
		result = multierror.Append(result, err)
	}

	if err := validateSnapshotters(m, spec); err != nil {
		result = multierror.Append(result, err)
	}

	if err := validateStructs(m, spec); err != nil {
		result = multierror.Append(result, err)
	}

	if err := validateGadgetParams(m, spec); err != nil {
		result = multierror.Append(result, err)
	}

	return result
}

func validateTracers(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var result error

	for name, t := range m.Tracers {
		err := validateMapAndStruct(t.MapName, t.StructName, spec, m, validateTracerMap)
		if err != nil {
			result = multierror.Append(result, fmt.Errorf("validating tracer %q: %w", name, err))
		}
	}

	return result
}

// validateTracerMap only checks if the map type. It does not check the map
// value name and type because such a information is not available in the map
// definition for perf event arrays and ring buffers.
func validateTracerMap(tracerMap *ebpf.MapSpec, _ string) error {
	if tracerMap.Type != ebpf.RingBuf && tracerMap.Type != ebpf.PerfEventArray {
		return fmt.Errorf("map %q has a wrong type, expected: ringbuf or perf event array, got: %s",
			tracerMap.Name, tracerMap.Type)
	}
	return nil
}

func validateToppers(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var result error

	for name, t := range m.Toppers {
		err := validateMapAndStruct(t.MapName, t.StructName, spec, m, validateTopperMap)
		if err != nil {
			result = multierror.Append(result, fmt.Errorf("validating topper %q: %w", name, err))
		}
	}

	return result
}

func validateTopperMap(topperMap *ebpf.MapSpec, expectedStructName string) error {
	if topperMap.Type != ebpf.Hash {
		return fmt.Errorf("map %q has a wrong type, expected: hash, got: %s",
			topperMap.Name, topperMap.Type)
	}

	if topperMap.Value == nil {
		return fmt.Errorf("map %q does not have BTF information for its values", topperMap.Name)
	}

	topperMapStruct, ok := topperMap.Value.(*btf.Struct)
	if !ok {
		return fmt.Errorf("map %q value is %q, expected \"struct\"",
			topperMap.Name, topperMap.Value.TypeName())
	}

	if expectedStructName != "" && topperMapStruct.Name != expectedStructName {
		return fmt.Errorf("map %q value name is %q, expected %q",
			topperMap.Name, topperMapStruct.Name, expectedStructName)
	}

	return nil
}

func validateSnapshotters(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var result error

	for name, snapshotter := range m.Snapshotters {
		if snapshotter.StructName == "" {
			result = multierror.Append(result, fmt.Errorf("snapshotter %q is missing structName", name))
			continue
		}

		if _, ok := m.Structs[snapshotter.StructName]; !ok {
			result = multierror.Append(result, fmt.Errorf("snapshotter %q references unknown struct %q", name, snapshotter.StructName))
		}
	}

	return result
}

// validateMapAndStruct fully validates the map, while the struct is only
// checked for existence in the Structs section of the metadata as it will be
// validated with the rest of the structs.
func validateMapAndStruct(mapName, structName string,
	spec *ebpf.CollectionSpec,
	m *GadgetMetadata,
	validateMap func(*ebpf.MapSpec, string) error,
) (result error) {
	if mapName == "" {
		result = multierror.Append(result, errors.New("missing mapName"))
	} else {
		ebpfMap, ok := spec.Maps[mapName]
		if !ok {
			return fmt.Errorf("map %q not found in eBPF object", mapName)
		}

		if err := validateMap(ebpfMap, structName); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if structName == "" {
		result = multierror.Append(result, errors.New("missing structName"))
	} else if _, ok := m.Structs[structName]; !ok {
		result = multierror.Append(result, fmt.Errorf("referencing unknown struct %q", structName))
	}

	return
}

func validateStructs(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var result error

	for name, mapStruct := range m.Structs {
		var btfStruct *btf.Struct
		if err := spec.Types.TypeByName(name, &btfStruct); err != nil {
			result = multierror.Append(result, fmt.Errorf("looking for struct %q in eBPF object: %w", name, err))
			continue
		}

		mapStructFields := make(map[string]Field, len(mapStruct.Fields))
		for _, f := range mapStruct.Fields {
			mapStructFields[f.Name] = f
		}

		btfStructFields := make(map[string]btf.Member, len(btfStruct.Members))
		for _, m := range btfStruct.Members {
			btfStructFields[m.Name] = m
		}

		for fieldName := range mapStructFields {
			if _, ok := btfStructFields[fieldName]; !ok {
				result = multierror.Append(result, fmt.Errorf("field %q not found in eBPF struct %q", fieldName, name))
			}
		}
	}

	return result
}

func validateEbpfParams(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var result error
	for varName := range m.EBPFParams {
		if err := checkParamVar(spec, varName); err != nil {
			result = multierror.Append(result, err)
		}
		if len(m.EBPFParams[varName].Key) == 0 {
			result = multierror.Append(result, fmt.Errorf("param %q has an empty key", varName))
		}
	}
	return result
}

func validateGadgetParams(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var result error
	for _, p := range spec.Programs {
		switch p.Type {
		// Networking programs provide an interface name to attach to
		case ebpf.SchedCLS:
			if len(m.GadgetParams) == 0 {
				result = multierror.Append(result, fmt.Errorf("there aren't gadget parameters"))
			} else {
				if _, ok := m.GadgetParams[IfaceParam]; !ok {
					result = multierror.Append(result, fmt.Errorf("iface param not found"))
				}
			}
		}
	}
	return result
}
