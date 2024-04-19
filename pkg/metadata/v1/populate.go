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
	"bytes"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// Populate fills the metadata from its ebpf spec
func (m *GadgetMetadata) Populate(spec *ebpf.CollectionSpec) error {
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

	if err := populateTracers(m, spec); err != nil {
		return fmt.Errorf("handling trace maps: %w", err)
	}

	if err := populateToppers(m, spec); err != nil {
		return fmt.Errorf("handling snapshotters: %w", err)
	}

	if err := populateSnapshotters(m, spec); err != nil {
		return fmt.Errorf("handling snapshotters: %w", err)
	}

	if err := populateEbpfParams(m, spec); err != nil {
		return fmt.Errorf("handling params: %w", err)
	}

	if err := populateGadgetParams(m, spec); err != nil {
		return fmt.Errorf("handling gadget params: %w", err)
	}

	return nil
}

func getColumnSize(typ btf.Type) uint {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return columns.MaxCharsInt8
			case 2:
				return columns.MaxCharsInt16
			case 4:
				return columns.MaxCharsInt32
			case 8:
				return columns.MaxCharsInt64

			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return columns.MaxCharsUint8
			case 2:
				return columns.MaxCharsUint16
			case 4:
				return columns.MaxCharsUint32
			case 8:
				return columns.MaxCharsUint64
			}
		case btf.Bool:
			return columns.MaxCharsBool
		case btf.Char:
			return columns.MaxCharsChar
		}
	case *btf.Typedef:
		typ := btfhelpers.GetUnderlyingType(typedMember)
		return getColumnSize(typ)
	}

	return DefaultColumnWidth
}

func populateTracers(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	tracerInfo, err := getTracerInfo(spec)
	if err != nil {
		return err
	}
	if tracerInfo == nil {
		log.Debug("No tracer found in eBPF object")
		return nil
	}

	if m.Tracers == nil {
		m.Tracers = make(map[string]Tracer)
	}

	tracerMap := spec.Maps[tracerInfo.mapName]
	if tracerMap == nil {
		return fmt.Errorf("map %q not found in eBPF object", tracerInfo.mapName)
	}

	if err := validateTracerMap(tracerMap, ""); err != nil {
		return fmt.Errorf("tracer map is invalid: %w", err)
	}

	var tracerMapStruct *btf.Struct
	if err := spec.Types.TypeByName(tracerInfo.eventType, &tracerMapStruct); err != nil {
		return fmt.Errorf("finding struct %q in eBPF object: %w", tracerInfo.eventType, err)
	}

	if _, found := m.Tracers[tracerInfo.name]; !found {
		log.Debugf("Adding tracer %q with map %q and struct %q",
			tracerInfo.name, tracerMap.Name, tracerMapStruct.Name)

		m.Tracers[tracerInfo.name] = Tracer{
			MapName:    tracerMap.Name,
			StructName: tracerMapStruct.Name,
		}
	} else {
		log.Debugf("Tracer %q already defined, skipping", tracerInfo.name)
	}

	if err := populateStruct(m, tracerMapStruct); err != nil {
		return fmt.Errorf("populating struct: %w", err)
	}

	return nil
}

func populateToppers(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	topperInfo, err := getTopperInfo(spec)
	if err != nil {
		return err
	}
	if topperInfo == nil {
		log.Debug("No topper found in eBPF object")
		return nil
	}

	if m.Toppers == nil {
		m.Toppers = make(map[string]Topper)
	}

	topperMap := spec.Maps[topperInfo.mapName]
	if topperMap == nil {
		return fmt.Errorf("map %q not found in eBPF object", topperInfo.mapName)
	}

	t, found := m.Toppers[topperInfo.name]
	if err := validateTopperMap(topperMap, t.StructName); err != nil {
		return err
	}

	var topperMapStruct *btf.Struct
	if err := spec.Types.TypeByName(topperMap.Value.TypeName(), &topperMapStruct); err != nil {
		return fmt.Errorf("finding struct %q in eBPF object: %w", topperMap.Value.TypeName(), err)
	}

	if !found {
		log.Debugf("Adding topper %q with map %q and struct %q",
			topperInfo.name, topperMap.Name, topperMapStruct.Name)

		m.Toppers[topperInfo.name] = Topper{
			MapName:    topperMap.Name,
			StructName: topperMapStruct.Name,
		}
	} else {
		log.Debugf("Topper %q already defined, skipping", topperInfo.name)
	}

	if err := populateStruct(m, topperMapStruct); err != nil {
		return fmt.Errorf("populating struct: %w", err)
	}

	return nil
}

type tracerInfo struct {
	name      string
	mapName   string
	eventType string
}

// getTracerInfo returns the tracer info generated with GADGET_TRACER().
// If there are multiple annotations only the first one is returned.
func getTracerInfo(spec *ebpf.CollectionSpec) (*tracerInfo, error) {
	tracersInfo, err := getGadgetIdentByPrefix(spec, tracerInfoPrefix)
	if err != nil {
		return nil, err
	}
	if len(tracersInfo) == 0 {
		return nil, nil
	}

	if len(tracersInfo) > 1 {
		log.Warnf("multiple tracers found, using %q", tracersInfo[0])
	}

	parts := strings.Split(tracersInfo[0], "___")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid tracer info: %q", tracersInfo[0])
	}

	return &tracerInfo{
		name:      parts[0],
		mapName:   parts[1],
		eventType: parts[2],
	}, nil
}

type topperInfo struct {
	name    string
	mapName string
}

// getTopperInfo returns the topper info generated with GADGET_TOPPER().
// If there are multiple annotations only the first one is returned.
func getTopperInfo(spec *ebpf.CollectionSpec) (*topperInfo, error) {
	toppersInfo, err := getGadgetIdentByPrefix(spec, topperInfoPrefix)
	if err != nil {
		return nil, fmt.Errorf("getting topper info: %w", err)
	}
	if len(toppersInfo) == 0 {
		return nil, nil
	}

	if len(toppersInfo) > 1 {
		log.Warnf("multiple toppers found, using %q", toppersInfo[0])
	}

	parts := strings.Split(toppersInfo[0], "___")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid topper info: %q", toppersInfo[0])
	}

	return &topperInfo{
		name:    parts[0],
		mapName: parts[1],
	}, nil
}

func populateStruct(m *GadgetMetadata, btfStruct *btf.Struct) error {
	if m.Structs == nil {
		m.Structs = make(map[string]Struct)
	}

	w := bytes.NewBuffer(nil)

	fmt.Printf("******\n")

	formatter := btf.GoFormatter{}

	dec, _ := formatter.TypeDeclaration("mystruct", btfStruct)
	w.WriteString(dec)

	fmt.Printf("declaration is: %s\n", w.String())

	fmt.Printf("******\n")

	gadgetStruct := m.Structs[btfStruct.Name]
	existingFields := make(map[string]struct{})
	for _, field := range gadgetStruct.Fields {
		existingFields[field.Name] = struct{}{}
	}

	for _, member := range btfStruct.Members {
		// check if field already exists
		if _, ok := existingFields[member.Name]; ok {
			log.Debugf("Field %q already exists, skipping", member.Name)
			continue
		}

		log.Debugf("Adding field %q", member.Name)
		field := Field{
			Name:        member.Name,
			Description: "TODO: Fill field description",
			Attributes: FieldAttributes{
				Width:     getColumnSize(member.Type),
				Alignment: AlignmentLeft,
				Ellipsis:  EllipsisEnd,
			},
		}

		gadgetStruct.Fields = append(gadgetStruct.Fields, field)
	}

	m.Structs[btfStruct.Name] = gadgetStruct

	return nil
}

func populateEbpfParams(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	var result error

	paramNames, err := getGadgetIdentByPrefix(spec, paramPrefix)
	if err != nil {
		result = multierror.Append(result, err)
	}

	for _, name := range paramNames {
		var btfVar *btf.Var
		err := spec.Types.TypeByName(name, &btfVar)
		if err != nil {
			result = multierror.Append(result, fmt.Errorf("looking variable %q up: %w", name, err))
			continue
		}

		err = checkParamVar(spec, name)
		if err != nil {
			result = multierror.Append(result, err)
			continue
		}

		if m.EBPFParams == nil {
			m.EBPFParams = make(map[string]EBPFParam)
		}

		if _, found := m.EBPFParams[name]; found {
			log.Debugf("Param %q already defined, skipping", name)
			continue
		}

		log.Debugf("Adding param %q", name)
		m.EBPFParams[name] = EBPFParam{
			ParamDesc: params.ParamDesc{
				Key:         name,
				Description: "TODO: Fill parameter description",
			},
		}
	}

	return result
}

func populateGadgetParams(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	for _, p := range spec.Programs {
		switch p.Type {
		// Networking programs provide an interface name to attach to
		case ebpf.SchedCLS:
			if m.GadgetParams == nil {
				m.GadgetParams = make(map[string]params.ParamDesc)
			}

			m.GadgetParams[IfaceParam] = params.ParamDesc{
				Key:         IfaceParam,
				Description: "Network interface to attach to",
			}
		}
	}

	return nil
}

func checkParamVar(spec *ebpf.CollectionSpec, name string) error {
	var result error

	var btfVar *btf.Var
	err := spec.Types.TypeByName(name, &btfVar)
	if err != nil {
		result = multierror.Append(result, fmt.Errorf("variable %q not found in eBPF object: %w", name, err))
		return result
	}
	if btfVar.Linkage != btf.GlobalVar {
		result = multierror.Append(result, fmt.Errorf("%q is not a global variable", name))
	}
	btfConst, ok := btfVar.Type.(*btf.Const)
	if !ok {
		result = multierror.Append(result, fmt.Errorf("%q is not const", name))
		return result
	}
	_, ok = btfConst.Type.(*btf.Volatile)
	if !ok {
		result = multierror.Append(result, fmt.Errorf("%q is not volatile", name))
		return result
	}

	return result
}

func populateSnapshotters(m *GadgetMetadata, spec *ebpf.CollectionSpec) error {
	snapshottersNameAndType, _ := getGadgetIdentByPrefix(spec, snapshottersPrefix)
	if len(snapshottersNameAndType) == 0 {
		log.Debug("No snapshotters found")
		return nil
	}

	if len(snapshottersNameAndType) > 1 {
		log.Warnf("Multiple snapshotters found, using %q", snapshottersNameAndType[0])
	}

	snapshotterNameAndType := snapshottersNameAndType[0]

	if m.Snapshotters == nil {
		m.Snapshotters = make(map[string]Snapshotter)
	}

	parts := strings.Split(snapshotterNameAndType, "___")
	if len(parts) != 2 {
		return fmt.Errorf("invalid snapshotter annotation: %q", snapshotterNameAndType)
	}
	sname := parts[0]
	stype := parts[1]

	var btfStruct *btf.Struct
	spec.Types.TypeByName(stype, &btfStruct)

	if btfStruct == nil {
		return fmt.Errorf("struct %q not found", stype)
	}

	_, ok := m.Snapshotters[sname]
	if !ok {
		log.Debugf("Adding snapshotter %q", sname)
		m.Snapshotters[sname] = Snapshotter{
			StructName: btfStruct.Name,
		}
	} else {
		log.Debugf("Snapshotter %q already defined, skipping", sname)
	}

	if err := populateStruct(m, btfStruct); err != nil {
		return fmt.Errorf("populating struct: %w", err)
	}

	return nil
}

// getGadgetIdentByPrefix returns the strings generated by GADGET_ macros.
func getGadgetIdentByPrefix(spec *ebpf.CollectionSpec, prefix string) ([]string, error) {
	var resultNames []string
	var resultError error

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
			resultError = multierror.Append(resultError, fmt.Errorf("%q is not a global variable", btfVar.Name))
		}
		btfPtr, ok := btfVar.Type.(*btf.Pointer)
		if !ok {
			resultError = multierror.Append(resultError, fmt.Errorf("%q is not a pointer", btfVar.Name))
			continue
		}
		btfConst, ok := btfPtr.Target.(*btf.Const)
		if !ok {
			resultError = multierror.Append(resultError, fmt.Errorf("%q is not const", btfVar.Name))
			continue
		}
		_, ok = btfConst.Type.(*btf.Void)
		if !ok {
			resultError = multierror.Append(resultError, fmt.Errorf("%q is not a const void pointer", btfVar.Name))
			continue
		}

		resultNames = append(resultNames, strings.TrimPrefix(btfVar.Name, prefix))
	}

	return resultNames, resultError
}
