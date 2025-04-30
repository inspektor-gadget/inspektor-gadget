// Copyright 2023-2024 The Inspektor Gadget authors
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

package types

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	log "github.com/sirupsen/logrus"

	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// Keep this aligned with include/gadget/macros.h
const (
	// Prefix used to mark tracer maps
	tracerInfoPrefix = "gadget_tracer_"

	// Prefix used to mark snapshotters structs
	snapshottersPrefix = "gadget_snapshotter_"

	// Prefix used to mark mapIters info
	mapIterInfoPrefix = "gadget_mapiter_"

	// Prefix used to mark eBPF params
	paramPrefix = "gadget_param_"
)

func Validate(m *metadatav1.GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var errs []error

	if m.Name == "" {
		errs = append(errs, errors.New("gadget name is required"))
	}

	errs = append(errs, validateEbpfParams(m, spec))

	return errors.Join(errs...)
}

func validateEbpfParams(m *metadatav1.GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var errs []error

	if m.Params == nil {
		return nil
	}

	ebpfParams := m.Params["ebpf"]

	for varName := range ebpfParams {
		errs = append(errs, checkParamVar(spec, varName))
		if len(ebpfParams[varName].Key) == 0 {
			errs = append(errs, fmt.Errorf("param %q has an empty key", varName))
		}
	}
	return errors.Join(errs...)
}

// Populate fills the metadata from its ebpf spec
func Populate(m *metadatav1.GadgetMetadata, spec *ebpf.CollectionSpec) error {
	if m.Name == "" {
		m.Name = "TODO: Fill the gadget name"
	}

	if m.Description == "" {
		m.Description = "TODO: Fill the gadget description"
	}

	if m.HomepageURL == "" {
		m.HomepageURL = "TODO: Fill the gadget homepage URL"
	}

	if m.DocumentationURL == "" {
		m.DocumentationURL = "TODO: Fill the gadget documentation URL"
	}

	if m.SourceURL == "" {
		m.SourceURL = "TODO: Fill the gadget source code URL"
	}

	if m.DataSources == nil {
		m.DataSources = make(map[string]*metadatav1.DataSource)
	}

	if err := populateTracers(m, spec); err != nil {
		return fmt.Errorf("handling tracers: %w", err)
	}

	if err := populateMapIters(m, spec); err != nil {
		return fmt.Errorf("handling mapIters: %w", err)
	}

	if err := populateSnapshotters(m, spec); err != nil {
		return fmt.Errorf("handling snapshotters: %w", err)
	}

	if err := populateEbpfParams(m, spec); err != nil {
		return fmt.Errorf("handling params: %w", err)
	}

	return nil
}

func populateTracers(m *metadatav1.GadgetMetadata, spec *ebpf.CollectionSpec) error {
	tracersInfo, err := getTracerInfo(spec)
	if err != nil {
		return err
	}

	for _, tracerInfo := range tracersInfo {
		tracerMap := spec.Maps[tracerInfo.mapName]
		if tracerMap == nil {
			return fmt.Errorf("map %q not found in eBPF object", tracerInfo.mapName)
		}

		if err := validateTracerMap(tracerMap); err != nil {
			return fmt.Errorf("tracer map is invalid: %w", err)
		}

		var tracerMapStruct *btf.Struct
		if err := spec.Types.TypeByName(tracerInfo.structName, &tracerMapStruct); err != nil {
			return fmt.Errorf("finding struct %q in eBPF object: %w", tracerInfo.structName, err)
		}

		if _, found := m.DataSources[tracerInfo.name]; !found {
			log.Debugf("Adding datasource %q for tracer with map %q and struct %q",
				tracerInfo.name, tracerMap.Name, tracerMapStruct.Name)

			m.DataSources[tracerInfo.name] = &metadatav1.DataSource{
				Fields: make(map[string]metadatav1.Field),
			}
		}

		ds := m.DataSources[tracerInfo.name]

		if err := populateDatasourceFields(ds, tracerMapStruct); err != nil {
			return fmt.Errorf("populating struct: %w", err)
		}
	}

	return nil
}

// validateTracerMap only checks the map type. It does not check the map name
// and type because that information is not available in the map definition for
// perf event arrays and ring buffers.
func validateTracerMap(tracerMap *ebpf.MapSpec) error {
	if tracerMap.Type != ebpf.RingBuf && tracerMap.Type != ebpf.PerfEventArray {
		return fmt.Errorf("map %q has a wrong type, expected: ringbuf or perf event array, got: %s",
			tracerMap.Name, tracerMap.Type)
	}
	return nil
}

func populateMapIters(m *metadatav1.GadgetMetadata, spec *ebpf.CollectionSpec) error {
	mapItersInfo, err := getMapIterInfo(spec)
	if err != nil {
		return err
	}

	for _, mapIterInfo := range mapItersInfo {
		iterMap, ok := spec.Maps[mapIterInfo.mapName]
		if !ok {
			return fmt.Errorf("map %q not found in eBPF object", mapIterInfo.mapName)
		}

		if err := validateMapToIter(iterMap); err != nil {
			return fmt.Errorf("mapIter map is invalid: %w", err)
		}

		keyStruct, ok := iterMap.Key.(*btf.Struct)
		if !ok {
			return fmt.Errorf("map %q key is not a struct", mapIterInfo.mapName)
		}

		valStruct, ok := iterMap.Value.(*btf.Struct)
		if !ok {
			return fmt.Errorf("map %q value is not a struct", mapIterInfo.mapName)
		}

		if iterMap.KeySize != keyStruct.Size || iterMap.ValueSize != valStruct.Size {
			return fmt.Errorf("key/value sizes of map %q does not match size of structs", mapIterInfo.name)
		}

		if _, found := m.DataSources[mapIterInfo.name]; !found {
			log.Debugf("Adding datasource %q for mapIter with map %q, key %q and value %q",
				mapIterInfo.name, iterMap.Name, keyStruct.Name, valStruct.Name)

			m.DataSources[mapIterInfo.name] = &metadatav1.DataSource{
				Fields: make(map[string]metadatav1.Field),
			}
		}

		ds := m.DataSources[mapIterInfo.name]

		if err := populateDatasourceFields(ds, keyStruct); err != nil {
			return fmt.Errorf("populating struct: %w", err)
		}

		if err := populateDatasourceFields(ds, valStruct); err != nil {
			return fmt.Errorf("populating struct: %w", err)
		}
	}

	return nil
}

// validateMapToIter only checks the map type. It does not check the map name
// and type because that information is not available in the map definition for
// perf event arrays and ring buffers.
func validateMapToIter(mapToIter *ebpf.MapSpec) error {
	if mapToIter.Type != ebpf.Hash {
		return fmt.Errorf("map %q has a wrong type, expected: hash, got: %s",
			mapToIter.Name, mapToIter.Type)
	}
	return nil
}

func populateSnapshotters(m *metadatav1.GadgetMetadata, spec *ebpf.CollectionSpec) error {
	snapshottersDef, _ := GetGadgetIdentByPrefix(spec, snapshottersPrefix)

	for _, snapshotterDef := range snapshottersDef {
		parts := strings.Split(snapshotterDef, "___")
		if len(parts) < 3 {
			// At least one program is required
			return fmt.Errorf("invalid snapshotter definition, expected format: <name>___<structName>___<program1>___...___<programN>, got %q",
				snapshotterDef)
		}

		sname := parts[0]
		stype := parts[1]

		if err := validateSnapshotterPrograms(spec, parts[2:]); err != nil {
			return fmt.Errorf("validating snapshotter %q programs: %w", sname, err)
		}

		var btfStruct *btf.Struct
		spec.Types.TypeByName(stype, &btfStruct)

		if btfStruct == nil {
			return fmt.Errorf("struct %q not found", stype)
		}

		if _, found := m.DataSources[sname]; !found {
			log.Debugf("Adding datasource %q for snapshoter with struct %q", sname, stype)

			m.DataSources[sname] = &metadatav1.DataSource{
				Fields: make(map[string]metadatav1.Field),
			}
		}

		ds := m.DataSources[sname]

		if err := populateDatasourceFields(ds, btfStruct); err != nil {
			return fmt.Errorf("populating struct: %w", err)
		}

	}

	return nil
}

func validateSnapshotterPrograms(spec *ebpf.CollectionSpec, programs []string) error {
	for _, program := range programs {
		if program == "" {
			return errors.New("empty program name")
		}

		// Check if the program is in the eBPF object
		p, ok := spec.Programs[program]
		if !ok {
			return fmt.Errorf("program %q not found in eBPF object", program)
		}

		if p.Type != ebpf.Tracing || !strings.HasPrefix(p.SectionName, "iter/") {
			return fmt.Errorf("invalid program %q: expecting type %q and section name prefix \"iter/\", got %q and %q",
				program, ebpf.Tracing, p.Type, p.SectionName)
		}
	}
	return nil
}

func populateDatasourceFields(ds *metadatav1.DataSource, btfStruct *btf.Struct) error {
	if ds.Fields == nil {
		ds.Fields = make(map[string]metadatav1.Field)
	}

	existingFields := make(map[string]struct{})
	for name := range ds.Fields {
		existingFields[name] = struct{}{}
	}

	for _, member := range btfStruct.Members {
		// check if field already exists
		if _, ok := existingFields[member.Name]; ok {
			log.Debugf("Field %q already exists, skipping", member.Name)
			continue
		}

		log.Debugf("Adding field %q", member.Name)
		field := metadatav1.Field{
			Annotations: map[string]string{
				"description": "TODO: Fill field description",
			},
		}

		ds.Fields[member.Name] = field
	}

	return nil
}

// GetGadgetIdentByPrefix returns the strings generated by GADGET_ macros.
func GetGadgetIdentByPrefix(spec *ebpf.CollectionSpec, prefix string) ([]string, error) {
	var resultNames []string
	var errs []error

	it := spec.Types.Iterate()
	for it.Next() {
		btfVar, ok := it.Type.(*btf.Var)
		if !ok {
			continue
		}
		if !strings.HasPrefix(btfVar.Name, prefix) {
			continue
		}
		if btfVar.Linkage != btf.GlobalVar {
			errs = append(errs, fmt.Errorf("%q is not a global variable", btfVar.Name))
		}
		btfPtr, ok := btfVar.Type.(*btf.Pointer)
		if !ok {
			errs = append(errs, fmt.Errorf("%q is not a pointer", btfVar.Name))
			continue
		}
		btfConst, ok := btfPtr.Target.(*btf.Const)
		if !ok {
			errs = append(errs, fmt.Errorf("%q is not const", btfVar.Name))
			continue
		}
		_, ok = btfConst.Type.(*btf.Void)
		if !ok {
			errs = append(errs, fmt.Errorf("%q is not a const void pointer", btfVar.Name))
			continue
		}

		resultNames = append(resultNames, strings.TrimPrefix(btfVar.Name, prefix))
	}

	return resultNames, errors.Join(errs...)
}

type tracerInfo struct {
	name       string
	mapName    string
	structName string
}

// getTracerInfo returns the tracer info generated with GADGET_TRACER().
func getTracerInfo(spec *ebpf.CollectionSpec) ([]tracerInfo, error) {
	tracersInfo, err := GetGadgetIdentByPrefix(spec, tracerInfoPrefix)
	if err != nil {
		return nil, err
	}

	ret := make([]tracerInfo, 0, len(tracersInfo))

	for _, info := range tracersInfo {
		parts := strings.Split(info, "___")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid tracer info: %q", tracersInfo[0])
		}

		ret = append(ret, tracerInfo{
			name:       parts[0],
			mapName:    parts[1],
			structName: parts[2],
		})
	}

	return ret, nil
}

type mapIterInfo struct {
	name    string
	mapName string
}

// getMapIterInfo returns the mapIter info generated with GADGET_MAPITER().
func getMapIterInfo(spec *ebpf.CollectionSpec) ([]mapIterInfo, error) {
	mapItersInfo, err := GetGadgetIdentByPrefix(spec, mapIterInfoPrefix)
	if err != nil {
		return nil, err
	}

	ret := make([]mapIterInfo, 0, len(mapItersInfo))

	for _, info := range mapItersInfo {
		parts := strings.Split(info, "___")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mapIter info: %q", mapItersInfo[0])
		}

		ret = append(ret, mapIterInfo{
			name:    parts[0],
			mapName: parts[1],
		})
	}

	return ret, nil
}

func populateEbpfParams(m *metadatav1.GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var errs []error

	paramNames, err := GetGadgetIdentByPrefix(spec, paramPrefix)
	errs = append(errs, err)

	for _, name := range paramNames {
		var btfVar *btf.Var
		err := spec.Types.TypeByName(name, &btfVar)
		if err != nil {
			errs = append(errs, fmt.Errorf("looking variable %q up: %w", name, err))
			continue
		}

		err = checkParamVar(spec, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if m.Params == nil {
			m.Params = make(map[string]map[string]params.ParamDesc)
		}

		if m.Params["ebpf"] == nil {
			m.Params["ebpf"] = make(map[string]params.ParamDesc)
		}

		ebpfParams := m.Params["ebpf"]

		if _, found := ebpfParams[name]; found {
			log.Debugf("Param %q already defined, skipping", name)
			continue
		}

		log.Debugf("Adding param %q", name)
		ebpfParams[name] = params.ParamDesc{
			Key:         name,
			Description: "TODO: Fill parameter description",
		}
	}

	return errors.Join(errs...)
}

func checkParamVar(spec *ebpf.CollectionSpec, name string) error {
	var btfVar *btf.Var
	err := spec.Types.TypeByName(name, &btfVar)
	if err != nil {
		return fmt.Errorf("variable %q not found in eBPF object: %w", name, err)
	}
	if btfVar.Linkage != btf.GlobalVar {
		return fmt.Errorf("%q is not a global variable", name)
	}
	typ := btfVar.Type
	if btfArr, ok := typ.(*btf.Array); ok {
		// Example of valid array of constants:
		// const volatile gadget_comm targ_comm[TASK_COMM_LEN] = {};
		typ = btfArr.Type
	}
	btfConst, ok := typ.(*btf.Const)
	if !ok {
		return fmt.Errorf("%q is not const", name)
	}
	_, ok = btfConst.Type.(*btf.Volatile)
	if !ok {
		return fmt.Errorf("%q is not volatile", name)
	}

	return nil
}
