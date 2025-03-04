// Copyright 2025 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type extraInfoMap struct {
	Name string
	Type string
}

type extraInfoProgram struct {
	Section string
	Source  string
}

type extraInfoVariable struct {
	Name   string
	Offset uint64
	Size   uint64
	Map    string
}

func (i *ebpfInstance) addExtraInfo(gadgetCtx operators.GadgetContext) error {
	ef, err := elf.NewFile(bytes.NewReader(i.program))
	if err != nil {
		return fmt.Errorf("parsing elf file: %w", err)
	}
	var sections []string
	var maps []*extraInfoMap
	var programs []*extraInfoProgram
	var variables []*extraInfoVariable

	// Add sections
	for _, sec := range ef.Sections {
		sections = append(sections, sec.Name)
	}
	sectionsJson, _ := json.Marshal(sections)

	// Add maps
	for name, m := range i.collectionSpec.Maps {
		if name == ".rodata" || name == ".bss" {
			continue
		}
		maps = append(maps, &extraInfoMap{
			Name: name,
			Type: m.Type.String(),
		})
	}
	mapsJson, _ := json.Marshal(maps)

	// Add programs
	for _, p := range i.collectionSpec.Programs {
		programs = append(programs, &extraInfoProgram{
			Section: p.SectionName,
			Source:  p.Instructions.String(),
		})
	}
	programsJson, _ := json.Marshal(programs)

	// Add variables
	for name, v := range i.collectionSpec.Variables {
		variables = append(variables, &extraInfoVariable{
			Name:   name,
			Offset: v.Offset(),
			Size:   v.Size(),
			Map:    v.MapName(),
		})
	}
	variablesJson, _ := json.Marshal(variables)

	ebpfInfo := &api.ExtraInfo{
		Data: make(map[string]*api.GadgetInspectAddendum),
	}
	ebpfInfo.Data["ebpf.sections"] = &api.GadgetInspectAddendum{
		ContentType: "application/json",
		Content:     []byte(sectionsJson),
	}
	ebpfInfo.Data["ebpf.maps"] = &api.GadgetInspectAddendum{
		ContentType: "application/json",
		Content:     []byte(mapsJson),
	}
	ebpfInfo.Data["ebpf.programs"] = &api.GadgetInspectAddendum{
		ContentType: "application/json",
		Content:     []byte(programsJson),
	}
	ebpfInfo.Data["ebpf.variables"] = &api.GadgetInspectAddendum{
		ContentType: "application/json",
		Content:     []byte(variablesJson),
	}

	gadgetCtx.SetVar("extraInfo.ebpf", ebpfInfo)

	return nil
}
