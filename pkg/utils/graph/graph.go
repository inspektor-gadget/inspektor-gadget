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

package graphutils

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func GenerateFlowchartMermaidGraph(collectionSpec *ebpf.CollectionSpec) (string, error) {
	graph := "flowchart LR\n"

	var mapsList []*ebpf.MapSpec
	for _, m := range collectionSpec.Maps {
		if m.Name == ".rodata" || m.Name == ".bss" {
			continue
		}
		mapsList = append(mapsList, m)
	}
	sort.Slice(mapsList, func(i, j int) bool {
		return mapsList[i].Name < mapsList[j].Name
	})

	var progsList []*ebpf.ProgramSpec
	for _, p := range collectionSpec.Programs {
		progsList = append(progsList, p)
	}
	sort.Slice(progsList, func(i, j int) bool {
		return progsList[i].Name < progsList[j].Name
	})
	for _, m := range mapsList {
		graph += fmt.Sprintf("%s[(\"%s\")]\n", m.Name, m.Name)
	}

	for _, prog := range progsList {
		references := make(map[string]bool)
		previousRef := map[asm.Register]string{}
		for _, ins := range prog.Instructions {
			if ins.IsBuiltinCall() {
				builtinFunc := asm.BuiltinFunc(ins.Constant)
				builtinFuncName := fmt.Sprint(builtinFunc)
				ref := ""
				if strings.HasPrefix(builtinFuncName, "FnMap") &&
					strings.HasSuffix(builtinFuncName, "Elem") {
					builtinFuncName = strings.TrimPrefix(builtinFuncName, "FnMap")
					builtinFuncName = strings.TrimSuffix(builtinFuncName, "Elem")
					ref = previousRef[asm.R1]
				} else if builtinFuncName == "FnPerfEventOutput" {
					builtinFuncName = strings.TrimPrefix(builtinFuncName, "FnPerf")
					ref = previousRef[asm.R2]
				}
				if ref != "" {
					references[ref+"\000"+builtinFuncName] = true
				}
			}
			if ref := ins.Reference(); ref != "" {
				previousRef[ins.Dst] = ref
			}
		}
		possibleVerbs := []string{
			"Lookup",
			"Update",
			"Delete",
		}

		referencesList := []string{}
		for ref := range references {
			referencesList = append(referencesList, ref)
		}
		sort.Strings(referencesList)
		for _, ref := range referencesList {
			if !references[ref] {
				continue
			}
			parts := strings.SplitN(ref, "\000", 2)
			fnName := parts[1]
			mapName := parts[0]
			// If several arrows exist, merge them
			verbs := []string{}
			for _, verb := range possibleVerbs {
				if references[mapName+"\000"+verb] {
					verbs = append(verbs, verb)
				}
			}
			if len(verbs) > 1 {
				for _, verb := range verbs {
					references[mapName+"\000"+verb] = false
				}
				fnName = strings.Join(verbs, "+")
			}
			graph += fmt.Sprintf("%s -- \"%s\" --> %s\n", prog.Name, fnName, mapName)
		}
		graph += fmt.Sprintf("%s[\"%s\"]\n", prog.Name, prog.Name)
	}
	return graph, nil
}
