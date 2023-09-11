// Copyright 2023 The Inspektor Gadget authors
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

package tracer

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"gopkg.in/yaml.v3"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	columns_json "github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/json"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

const (
	ProgramContent  = "prog"
	ParamDefinition = "definition"
	printMapPrefix  = "print_"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "run"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryNone
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	// Currently trace only
	return gadgets.TypeTrace
}

func (g *GadgetDesc) Description() string {
	return "Run a containerized gadget"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ProgramContent,
			Title:       "eBPF program",
			Description: "Compiled eBPF program",
			TypeHint:    params.TypeBytes,
		},
		{
			Key:         ParamDefinition,
			Title:       "Gadget definition",
			Description: "Gadget definition in yaml format",
			TypeHint:    params.TypeBytes,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func getUnderlyingType(tf *btf.Typedef) (btf.Type, error) {
	switch typedMember := tf.Type.(type) {
	case *btf.Typedef:
		return getUnderlyingType(typedMember)
	default:
		return typedMember, nil
	}
}

func loadSpec(progContent []byte) (*ebpf.CollectionSpec, error) {
	progReader := bytes.NewReader(progContent)
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil, fmt.Errorf("loading spec: %w", err)
	}
	return spec, err
}

// getPrintMap returns the first map with a "print_" prefix. If not found returns nil.
func getPrintMap(spec *ebpf.CollectionSpec) *ebpf.MapSpec {
	for _, m := range spec.Maps {
		if m.Type != ebpf.RingBuf && m.Type != ebpf.PerfEventArray {
			continue
		}

		if !strings.HasPrefix(m.Name, printMapPrefix) {
			continue
		}

		return m
	}

	return nil
}

func getEventTypeBTF(progContent []byte) (*btf.Struct, error) {
	spec, err := loadSpec(progContent)
	if err != nil {
		return nil, err
	}

	// Look for gadgets with a "print_" map
	printMap := getPrintMap(spec)
	if printMap != nil {
		valueStruct, ok := printMap.Value.(*btf.Struct)
		if !ok {
			return nil, fmt.Errorf("BPF map %q does not have BTF info for values", printMap.Name)
		}

		return valueStruct, nil
	}

	return nil, fmt.Errorf("the gadget doesn't provide any compatible way to show information")
}

func getType(typ btf.Type) reflect.Type {
	switch typedMember := typ.(type) {
	case *btf.Array:
		arrType := getSimpleType(typedMember.Type)
		if arrType == nil {
			return nil
		}
		return reflect.ArrayOf(int(typedMember.Nelems), arrType)
	default:
		return getSimpleType(typ)
	}
}

func getSimpleType(typ btf.Type) reflect.Type {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(int8(0))
			case 2:
				return reflect.TypeOf(int16(0))
			case 4:
				return reflect.TypeOf(int32(0))
			case 8:
				return reflect.TypeOf(int64(0))
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(uint8(0))
			case 2:
				return reflect.TypeOf(uint16(0))
			case 4:
				return reflect.TypeOf(uint32(0))
			case 8:
				return reflect.TypeOf(uint64(0))
			}
		case btf.Bool:
			return reflect.TypeOf(bool(false))
		case btf.Char:
			return reflect.TypeOf(uint8(0))
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return reflect.TypeOf(float32(0))
		case 8:
			return reflect.TypeOf(float64(0))
		}
	case *btf.Typedef:
		typ, _ := getUnderlyingType(typedMember)
		return getSimpleType(typ)
	}

	return nil
}

func addL3EndpointColumns(
	cols *columns.Columns[types.Event],
	name string,
	getEndpoint func(*types.Event) eventtypes.L3Endpoint,
) {
	cols.AddColumn(columns.Attributes{
		Name:     name + ".namespace",
		Template: "namespace",
	}, func(e *types.Event) any {
		return getEndpoint(e).Namespace
	})

	cols.AddColumn(columns.Attributes{
		Name: name + ".name",
	}, func(e *types.Event) any {
		return getEndpoint(e).Name
	})

	cols.AddColumn(columns.Attributes{
		Name: name + ".kind",
	}, func(e *types.Event) any {
		return string(getEndpoint(e).Kind)
	})

	cols.AddColumn(columns.Attributes{
		Name:     name + ".addr",
		Template: "ipaddr",
	}, func(e *types.Event) any {
		return getEndpoint(e).Addr
	})

	cols.AddColumn(columns.Attributes{
		Name:     name + ".v",
		Template: "ipversion",
	}, func(e *types.Event) any {
		return getEndpoint(e).Version
	})
}

func addL4EndpointColumns(
	cols *columns.Columns[types.Event],
	name string,
	getEndpoint func(*types.Event) eventtypes.L4Endpoint,
) {
	addL3EndpointColumns(cols, name, func(e *types.Event) eventtypes.L3Endpoint {
		return getEndpoint(e).L3Endpoint
	})

	cols.AddColumn(columns.Attributes{
		Name:     name + ".port",
		Template: "ipport",
	}, func(e *types.Event) any {
		return getEndpoint(e).Port
	})

	cols.AddColumn(columns.Attributes{
		Name:  name + ".proto",
		Width: 6,
	}, func(e *types.Event) any {
		return gadgets.ProtoString(int(getEndpoint(e).Proto))
	})
}

func (g *GadgetDesc) getColumns(params *params.Params, args []string) (*columns.Columns[types.Event], error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("no arguments expected: received %d", len(args))
	}
	progContent := params.Get(ProgramContent).AsBytes()
	definitionBytes := params.Get(ParamDefinition).AsBytes()
	if len(definitionBytes) == 0 {
		return nil, fmt.Errorf("no definition provided")
	}

	valueStruct, err := getEventTypeBTF(progContent)
	if err != nil {
		return nil, fmt.Errorf("getting value struct: %w", err)
	}

	cols := types.GetColumns()

	var gadgetDefinition types.GadgetDefinition

	if err := yaml.Unmarshal(definitionBytes, &gadgetDefinition); err != nil {
		return nil, fmt.Errorf("unmarshaling definition: %w", err)
	}

	colAttrs := map[string]columns.Attributes{}
	for _, col := range gadgetDefinition.ColumnsAttrs {
		colAttrs[col.Name] = col
	}

	fields := []columns.DynamicField{}

	l3endpointCounter := 0
	l4endpointCounter := 0

	for _, member := range valueStruct.Members {
		member := member

		attrs, ok := colAttrs[member.Name]
		if !ok {
			continue
		}

		switch typedMember := member.Type.(type) {
		case *btf.Struct:
			switch typedMember.Name {
			case gadgets.L3EndpointTypeName:
				// Take the value here, otherwise it'll use the wrong value after
				// it's increased
				index := l3endpointCounter
				// Add the column that is enriched
				eventtypes.MustAddVirtualL3EndpointColumn(cols, attrs, func(e *types.Event) eventtypes.L3Endpoint {
					if len(e.L3Endpoints) == 0 {
						return eventtypes.L3Endpoint{}
					}
					return e.L3Endpoints[index].L3Endpoint
				})
				// Add a single column for each field in the endpoint
				addL3EndpointColumns(cols, member.Name, func(e *types.Event) eventtypes.L3Endpoint {
					if len(e.L3Endpoints) == 0 {
						return eventtypes.L3Endpoint{}
					}
					return e.L3Endpoints[index].L3Endpoint
				})
				l3endpointCounter++
				continue
			case gadgets.L4EndpointTypeName:
				// Take the value here, otherwise it'll use the wrong value after
				// it's increased
				index := l4endpointCounter
				// Add the column that is enriched
				eventtypes.MustAddVirtualL4EndpointColumn(cols, attrs, func(e *types.Event) eventtypes.L4Endpoint {
					if len(e.L4Endpoints) == 0 {
						return eventtypes.L4Endpoint{}
					}
					return e.L4Endpoints[index].L4Endpoint
				})
				// Add a single column for each field in the endpoint
				addL4EndpointColumns(cols, member.Name, func(e *types.Event) eventtypes.L4Endpoint {
					if len(e.L4Endpoints) == 0 {
						return eventtypes.L4Endpoint{}
					}
					return e.L4Endpoints[index].L4Endpoint
				})
				l4endpointCounter++
				continue
			}
		}

		rType := getType(member.Type)
		if rType == nil {
			continue
		}

		field := columns.DynamicField{
			Attributes: &attrs,
			// TODO: remove once this is part of attributes
			Template: attrs.Template,
			Type:     rType,
			Offset:   uintptr(member.Offset.Bytes()),
		}

		fields = append(fields, field)
	}

	base := func(ev *types.Event) unsafe.Pointer {
		return unsafe.Pointer(&ev.RawData[0])
	}
	if err := cols.AddFields(fields, base); err != nil {
		return nil, fmt.Errorf("adding fields: %w", err)
	}
	return cols, nil
}

func (g *GadgetDesc) CustomParser(params *params.Params, args []string) (parser.Parser, error) {
	cols, err := g.getColumns(params, args)
	if err != nil {
		return nil, err
	}
	return parser.NewParser[types.Event](cols), nil
}

func (g *GadgetDesc) customJsonParser(params *params.Params, args []string, options ...columns_json.Option) (*columns_json.Formatter[types.Event], error) {
	cols, err := g.getColumns(params, args)
	if err != nil {
		return nil, err
	}
	return columns_json.NewFormatter(cols.ColumnMap, options...), nil
}

func (g *GadgetDesc) JSONConverter(params *params.Params, printer gadgets.Printer) func(ev any) {
	formatter, err := g.customJsonParser(params, []string{})
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return func(ev any) {
		event := ev.(*types.Event)
		printer.Output(formatter.FormatEntry(event))
	}
}

func (g *GadgetDesc) JSONPrettyConverter(params *params.Params, printer gadgets.Printer) func(ev any) {
	formatter, err := g.customJsonParser(params, []string{}, columns_json.WithPrettyPrint())
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return func(ev any) {
		event := ev.(*types.Event)
		printer.Output(formatter.FormatEntry(event))
	}
}

func (g *GadgetDesc) YAMLConverter(params *params.Params, printer gadgets.Printer) func(ev any) {
	formatter, err := g.customJsonParser(params, []string{})
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return func(ev any) {
		event := ev.(*types.Event)
		eventJson := formatter.FormatEntry(event)
		eventYaml, err := k8syaml.JSONToYAML([]byte(eventJson))
		if err != nil {
			printer.Logf(logger.WarnLevel, "converting json to yaml: %s", err)
			return
		}
		printer.Output(string(eventYaml))
	}
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func init() {
	if experimental.Enabled() {
		gadgetregistry.Register(&GadgetDesc{})
	}
}
