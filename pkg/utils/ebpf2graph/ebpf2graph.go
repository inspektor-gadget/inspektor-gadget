package ebpf2graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func GenerateFlowchartMermaidGraph(collectionSpec *ebpf.CollectionSpec) (string, error) {
	var graph strings.Builder
	graph.WriteString("flowchart LR\n")

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
		graph.WriteString(fmt.Sprintf("%s[(\"%s\")]\n", m.Name, m.Name))
	}

	for _, prog := range progsList {
		references := extractProgramReferences(prog)
		possibleVerbs := []string{"Lookup", "Update", "Delete"}

		referencesMap := make(map[string]bool)
		for _, ref := range references {
			referencesMap[ref] = true
		}
		for _, ref := range references {
			if !referencesMap[ref] {
				continue
			}
			parts := strings.SplitN(ref, "\000", 2)
			mapName := parts[0]
			fnName := parts[1]

			// Merge arrows if needed
			verbs := []string{}
			for _, verb := range possibleVerbs {
				if referencesMap[mapName+"\000"+verb] {
					verbs = append(verbs, verb)
				}
			}
			if len(verbs) > 1 {
				for _, verb := range verbs {
					referencesMap[mapName+"\000"+verb] = false
				}
				fnName = strings.Join(verbs, "+")
			}

			graph.WriteString(fmt.Sprintf("%s -- \"%s\" --> %s\n", prog.Name, fnName, mapName))
		}

		graph.WriteString(fmt.Sprintf("%s[\"%s\"]\n", prog.Name, prog.Name))
	}

	return graph.String(), nil
}

func GenerateSequenceMermaidGraph(collectionSpec *ebpf.CollectionSpec) (string, error) {
	var graph strings.Builder
	graph.WriteString("sequenceDiagram\n")

	var progsList []*ebpf.ProgramSpec
	graph.WriteString("box eBPF Programs\n")
	for _, p := range collectionSpec.Programs {
		progsList = append(progsList, p)
	}
	sort.Slice(progsList, func(i, j int) bool {
		return progsList[i].Name < progsList[j].Name
	})
	for _, p := range progsList {
		graph.WriteString(fmt.Sprintf("participant %s\n", p.Name))
	}
	graph.WriteString("end\n")

	mapSeen := make(map[string]bool)
	var orderedMapNames []string

	type event struct {
		sender   string
		receiver string
		label    string
	}
	var events []event

	for _, prog := range progsList {
		references := extractProgramReferences(prog)
		for _, ref := range references {
			parts := strings.SplitN(ref, "\000", 2)
			mapName := parts[0]
			label := parts[1]

			if !mapSeen[mapName] {
				mapSeen[mapName] = true
				orderedMapNames = append(orderedMapNames, mapName)
			}

			events = append(events, event{
				sender:   prog.Name,
				receiver: mapName,
				label:    label,
			})
		}
	}

	graph.WriteString("box eBPF Maps\n")
	for _, mName := range orderedMapNames {
		if mName == ".rodata" || mName == ".bss" {
			continue
		}
		graph.WriteString(fmt.Sprintf("participant %s\n", mName))
	}
	graph.WriteString("end\n")

	for _, e := range events {
		graph.WriteString(fmt.Sprintf("%s->>%s: %s\n", e.sender, e.receiver, e.label))
	}

	return graph.String(), nil
}

func extractProgramReferences(prog *ebpf.ProgramSpec) []string {
	var references []string
	previousRef := map[asm.Register]string{}

	addReference := func(ref string) {
		for _, r := range references {
			if r == ref {
				return // already exists
			}
		}
		references = append(references, ref)
	}

	for _, ins := range prog.Instructions {
		if ins.IsBuiltinCall() {
			builtinFunc := asm.BuiltinFunc(ins.Constant)
			builtinFuncName := fmt.Sprint(builtinFunc)
			var ref string

			switch {
			case strings.HasPrefix(builtinFuncName, "FnMap") && strings.HasSuffix(builtinFuncName, "Elem"):
				builtinFuncName = strings.TrimPrefix(builtinFuncName, "FnMap")
				builtinFuncName = strings.TrimSuffix(builtinFuncName, "Elem")
				ref = previousRef[asm.R1]
			case builtinFuncName == "FnPerfEventOutput":
				builtinFuncName = strings.TrimPrefix(builtinFuncName, "FnPerf")
				ref = previousRef[asm.R2]
			}

			if ref != "" {
				addReference(ref + "\000" + builtinFuncName)
			}
		}
		if ref := ins.Reference(); ref != "" {
			previousRef[ins.Dst] = ref
		}
	}

	return references
}
