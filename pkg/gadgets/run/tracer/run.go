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
	"net"
	"reflect"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	columns_json "github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/json"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci_helper"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

const (
	ProgramContent  = "prog"
	ParamDefinition = "definition"
	OCIImage        = "oci-image"
	printMapPrefix  = "print_"
)

type GadgetDesc struct {
	ebpfColAttrs map[string]columns.Attributes
}

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
		// Hardcoded for now
		{
			Key:          "authfile",
			Title:        "Auth file",
			DefaultValue: oci_helper.DefaultAuthFile,
			TypeHint:     params.TypeString,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return nil
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

func getPrintMap(spec *ebpf.CollectionSpec) (*ebpf.MapSpec, error) {
	for _, m := range spec.Maps {
		if m.Type != ebpf.RingBuf && m.Type != ebpf.PerfEventArray {
			continue
		}

		if !strings.HasPrefix(m.Name, printMapPrefix) {
			continue
		}

		return m, nil
	}

	return nil, fmt.Errorf("no BPF map with %q prefix found", printMapPrefix)
}

func getValueStructBTF(progContent []byte) (*btf.Struct, error) {
	spec, err := loadSpec(progContent)
	if err != nil {
		return nil, err
	}

	m, err := getPrintMap(spec)
	if err != nil {
		return nil, err
	}

	var valueStruct *btf.Struct
	var ok bool
	valueStruct, ok = m.Value.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("BPF map %q does not have BTF info for values", m.Name)
	}

	return valueStruct, nil
}

func getType(typ btf.Type) reflect.Type {
	switch typedMember := typ.(type) {
	case *btf.Array:
		arrType := getSimpleType(typedMember.Type)
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

func (g *GadgetDesc) getColumns(params *params.Params, args []string) (*columns.Columns[types.Event], error) {
	progContent := params.Get(ProgramContent).AsBytes()
	definitionBytes := params.Get(ParamDefinition).AsBytes()

	if len(progContent) == 0 || len(definitionBytes) == 0 {
		if len(args) != 1 {
			return nil, fmt.Errorf("one argument expected: received %d", len(args))
		}

		image, err := oci_helper.NormalizeImage(args[0])
		if err != nil {
			return nil, fmt.Errorf("normalize image: %w", err)
		}

		var imageStore oras.Target
		imageStore, err = oci_helper.GetLocalOciStore()
		if err != nil {
			logrus.Debugf("get oci store: %s", err)
			imageStore = oci_helper.GetMemoryStore()
		}
		authOpts := oci_helper.AuthOptions{
			AuthFile: params.Get("authfile").AsString(),
		}
		def, err := oci_helper.GetDefinition(imageStore, &authOpts, image)
		if err != nil {
			return nil, fmt.Errorf("get definition: %w", err)
		}
		definitionBytes = def

		prog, err := oci_helper.GetEbpfProgram(imageStore, &authOpts, image)
		if err != nil {
			return nil, fmt.Errorf("get ebpf program: %w", err)
		}
		progContent = prog
	}

	if len(definitionBytes) == 0 {
		return nil, fmt.Errorf("no definition provided")
	}

	valueStruct, err := getValueStructBTF(progContent)
	if err != nil {
		return nil, fmt.Errorf("getting value struct: %w", err)
	}

	cols := types.GetColumns()

	var gadgetDefinition types.GadgetDefinition

	if err := yaml.Unmarshal(definitionBytes, &gadgetDefinition); err != nil {
		return nil, fmt.Errorf("unmarshaling definition: %w", err)
	}

	g.ebpfColAttrs = map[string]columns.Attributes{}
	for _, col := range gadgetDefinition.ColumnsAttrs {
		g.ebpfColAttrs[col.Name] = col
	}

	fields := []columns.DynamicField{}

	for _, member := range valueStruct.Members {
		member := member

		attrs, ok := g.ebpfColAttrs[member.Name]
		if !ok {
			continue
		}

		switch typedMember := member.Type.(type) {
		case *btf.Union:
			if typedMember.Name == "ip_addr" && typedMember.Size >= 4 {
				cols.AddColumn(attrs, func(ev *types.Event) string {
					// TODO: Handle IPv6
					offset := uintptr(member.Offset.Bytes())
					ipSlice := unsafe.Slice(&ev.RawData[offset], 4)
					ipBytes := make(net.IP, 4)
					copy(ipBytes, ipSlice)
					return ipBytes.String()
				})
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

func (g *GadgetDesc) GetEbpfColAttrs() map[string]columns.Attributes {
	return g.ebpfColAttrs
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

func (g *GadgetDesc) JSONConverter(params *params.Params, args []string, printer gadgets.Printer) func(ev any) {
	formatter, err := g.customJsonParser(params, args)
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return func(ev any) {
		event := ev.(*types.Event)
		printer.Output(formatter.FormatEntry(event))
	}
}

func (g *GadgetDesc) JSONPrettyConverter(params *params.Params, args []string, printer gadgets.Printer) func(ev any) {
	formatter, err := g.customJsonParser(params, args, columns_json.WithPrettyPrint())
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return func(ev any) {
		event := ev.(*types.Event)
		printer.Output(formatter.FormatEntry(event))
	}
}

func (g *GadgetDesc) YAMLConverter(params *params.Params, args []string, printer gadgets.Printer) func(ev any) {
	formatter, err := g.customJsonParser(params, args)
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
