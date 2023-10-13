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
	"context"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	columns_json "github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/json"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

const (
	validateMetadataParam = "validate-metadata"
	authfileParam         = "authfile"
	insecureParam         = "insecure"
	pullParam             = "pull"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "run"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryNone
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	// Placeholder for gadget type. The actual type is determined at runtime by using
	// GetGadgetInfo()
	return gadgets.TypeRun
}

func (g *GadgetDesc) Description() string {
	return "Run a containerized gadget"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		// Hardcoded for now
		{
			Key:          authfileParam,
			Title:        "Auth file",
			DefaultValue: oci.DefaultAuthFile,
			TypeHint:     params.TypeString,
		},
		{
			Key:          validateMetadataParam,
			Title:        "Validate metadata",
			Description:  "Validate the gadget metadata before running the gadget",
			DefaultValue: "true",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          insecureParam,
			Title:        "Insecure connection",
			Description:  "Allow connections to HTTP only registries",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          pullParam,
			Title:        "Pull policy",
			Description:  "Specify when the gadget image should be pulled",
			DefaultValue: oci.PullImageMissing,
			PossibleValues: []string{
				oci.PullImageAlways,
				oci.PullImageMissing,
				oci.PullImageNever,
			},
			TypeHint: params.TypeString,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return nil
}

// getGadgetType returns the type of the gadget according to the gadget being run.
func getGadgetType(spec *ebpf.CollectionSpec,
	gadgetMetadata *types.GadgetMetadata,
) (gadgets.GadgetType, error) {
	switch {
	case len(gadgetMetadata.Tracers) > 0:
		return gadgets.TypeTrace, nil
	case len(gadgetMetadata.Snapshotters) > 0:
		return gadgets.TypeOneShot, nil
	default:
		return gadgets.TypeUnknown, fmt.Errorf("unknown gadget type")
	}
}

func getGadgetInfo(params *params.Params, args []string, logger logger.Logger) (*types.GadgetInfo, error) {
	authOpts := &oci.AuthOptions{
		AuthFile: params.Get(authfileParam).AsString(),
		Insecure: params.Get(insecureParam).AsBool(),
	}
	gadget, err := oci.GetGadgetImage(context.TODO(), args[0], authOpts, params.Get(pullParam).AsString())
	if err != nil {
		return nil, fmt.Errorf("getting gadget image: %w", err)
	}

	ret := &types.GadgetInfo{
		ProgContent:    gadget.EbpfObject,
		GadgetMetadata: &types.GadgetMetadata{},
	}

	spec, err := loadSpec(ret.ProgContent)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(gadget.Metadata, ocispec.DescriptorEmptyJSON.Data) {
		// metadata is not present. synthesize something on the fly from the spec
		if err := ret.GadgetMetadata.Populate(spec); err != nil {
			return nil, err
		}
	} else {
		validate := params.Get(validateMetadataParam).AsBool()

		if err := yaml.Unmarshal(gadget.Metadata, &ret.GadgetMetadata); err != nil {
			return nil, fmt.Errorf("unmarshaling metadata: %w", err)
		}

		if err := ret.GadgetMetadata.Validate(spec); err != nil {
			if !validate {
				logger.Warnf("gadget metadata is not valid: %v", err)
			} else {
				return nil, fmt.Errorf("gadget metadata is not valid: %w", err)
			}
		}
	}

	if err := fillTypeHints(spec, ret.GadgetMetadata.EBPFParams); err != nil {
		return nil, fmt.Errorf("fill parameters type hints: %w", err)
	}

	ret.GadgetType, err = getGadgetType(spec, ret.GadgetMetadata)
	if err != nil {
		return nil, err
	}

	ret.Columns, err = calculateColumnsForClient(ret.GadgetMetadata, gadget.EbpfObject)
	if err != nil {
		return nil, err
	}

	// Add some extra columns here, like from wasm
	// TODO: There is an architectural issue with this approach, the instance of NewBlobEvent()
	// cannot be passed to the tracer instance, so there is some code duplication and the code
	// in both places has to match in order to work.
	blob := NewBlobEvent()

	eventStructureName, eventStruct := getAnyMapElem(ret.GadgetMetadata.Structs)
	if eventStruct == nil {
		return nil, fmt.Errorf("struct not found in gadget metadata")
	}

	fields := []types.Field{}

	// any column
	uint64col, _ := AddField[uint64](blob, "uint64col")
	ret.Columns = append(ret.Columns, uint64col)
	fields = append(fields, types.Field{
		Name: "uint64col",
		Attributes: types.FieldAttributes{
			Width: 10,
		},
	})

	// int32 column
	int32col, _ := AddField[uint32](blob, "myint32")
	ret.Columns = append(ret.Columns, int32col)
	fields = append(fields, types.Field{
		Name: "myint32",
		Attributes: types.FieldAttributes{
			Width: 10,
		},
	})

	// Add a first string virtual column
	datecol, _ := blob.AddString("date")
	ret.Columns = append(ret.Columns, datecol)
	fields = append(fields, types.Field{
		Name: "date",
		Attributes: types.FieldAttributes{
			Width: 24,
		},
	})

	// Add another string virtual column
	stringcol, _ := blob.AddString("string")
	ret.Columns = append(ret.Columns, stringcol)
	fields = append(fields, types.Field{
		Name: "string",
		Attributes: types.FieldAttributes{
			Width: 10,
		},
	})

	eventStruct.Fields = append(eventStruct.Fields, fields...)
	ret.GadgetMetadata.Structs[*eventStructureName] = *eventStruct

	return ret, nil
}

func getTypeHint(typ btf.Type) params.TypeHint {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return params.TypeInt8
			case 2:
				return params.TypeInt16
			case 4:
				return params.TypeInt32
			case 8:
				return params.TypeInt64
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return params.TypeUint8
			case 2:
				return params.TypeUint16
			case 4:
				return params.TypeUint32
			case 8:
				return params.TypeUint64
			}
		case btf.Bool:
			return params.TypeBool
		case btf.Char:
			return params.TypeUint8
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return params.TypeFloat32
		case 8:
			return params.TypeFloat64
		}
	case *btf.Typedef:
		typ, err := getUnderlyingType(typedMember)
		if err != nil {
			return params.TypeUnknown
		}
		return getTypeHint(typ)
	case *btf.Volatile:
		return getTypeHint(typedMember.Type)
	}

	return params.TypeUnknown
}

// fillTypeHints fills the TypeHint field in the ebpf parameters according to the BTF information
// about those constants.
func fillTypeHints(spec *ebpf.CollectionSpec, params map[string]types.EBPFParam) error {
	for varName, p := range params {
		var btfVar *btf.Var
		err := spec.Types.TypeByName(varName, &btfVar)
		if err != nil {
			return fmt.Errorf("no BTF type found for: %s: %w", p.Key, err)
		}

		btfConst, ok := btfVar.Type.(*btf.Const)
		if !ok {
			return fmt.Errorf("type for %s is not a constant, got %s", p.Key, btfVar.Type)
		}

		p.TypeHint = getTypeHint(btfConst.Type)
		params[varName] = p
	}

	return nil
}

func (g *GadgetDesc) GetGadgetInfo(params *params.Params, args []string) (*types.GadgetInfo, error) {
	return getGadgetInfo(params, args, log.StandardLogger())
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

func reflectTypeFromType(typ types.Type) reflect.Type {
	if typ.Kind == types.KindArray {
		arrType := simpleReflectTypeFromType(typ.ArrayKind)
		if arrType == nil {
			return nil
		}
		return reflect.ArrayOf(typ.ArrayNElements, arrType)
	}

	return simpleReflectTypeFromType(typ.Kind)
}

func simpleReflectTypeFromType(kind types.Kind) reflect.Type {
	switch kind {
	case types.KindInt8:
		return reflect.TypeOf(int8(0))
	case types.KindInt16:
		return reflect.TypeOf(int16(0))
	case types.KindInt32:
		return reflect.TypeOf(int32(0))
	case types.KindInt64:
		return reflect.TypeOf(int64(0))
	case types.KindUint8:
		return reflect.TypeOf(uint8(0))
	case types.KindUint16:
		return reflect.TypeOf(uint16(0))
	case types.KindUint32:
		return reflect.TypeOf(uint32(0))
	case types.KindUint64:
		return reflect.TypeOf(uint64(0))
	case types.KindFloat32:
		return reflect.TypeOf(float32(0))
	case types.KindFloat64:
		return reflect.TypeOf(float64(0))
	case types.KindBool:
		return reflect.TypeOf(false)
	case types.KindString:
		return reflect.TypeOf("")
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

func field2ColumnAttrs(field *types.Field) columns.Attributes {
	fieldAttrs := field.Attributes

	defaultOpts := columns.GetDefault()

	attrs := columns.Attributes{
		Name:         field.Name,
		Alignment:    defaultOpts.DefaultAlignment,
		EllipsisType: defaultOpts.DefaultEllipsis,
		Width:        defaultOpts.DefaultWidth,
		Visible:      !fieldAttrs.Hidden,
	}

	if fieldAttrs.Width != 0 {
		attrs.Width = int(fieldAttrs.Width)
	}
	if fieldAttrs.MinWidth != 0 {
		attrs.MinWidth = int(fieldAttrs.MinWidth)
	}
	if fieldAttrs.MaxWidth != 0 {
		attrs.MaxWidth = int(fieldAttrs.MaxWidth)
	}
	if fieldAttrs.Template != "" {
		attrs.Template = fieldAttrs.Template
	}

	switch fieldAttrs.Alignment {
	case types.AlignmentLeft:
		attrs.Alignment = columns.AlignLeft
	case types.AlignmentRight:
		attrs.Alignment = columns.AlignRight
	}

	switch fieldAttrs.Ellipsis {
	case types.EllipsisStart:
		attrs.EllipsisType = ellipsis.Start
	case types.EllipsisMiddle:
		attrs.EllipsisType = ellipsis.Middle
	case types.EllipsisEnd:
		attrs.EllipsisType = ellipsis.End
	}

	return attrs
}

func (g *GadgetDesc) getColumns(info *types.GadgetInfo) (*columns.Columns[types.Event], error) {

	_, eventStruct := getAnyMapElem(info.GadgetMetadata.Structs)
	if eventStruct == nil {
		return nil, fmt.Errorf("struct not found in gadget metadata")
	}

	cols := types.GetColumns()

	ebpfFields := []columns.DynamicField{}
	blobFields := []columns.DynamicField{}

	l3endpointCounter := 0
	l4endpointCounter := 0
	timestampsCounter := 0

	fields := map[string]types.Field{}
	for _, field := range eventStruct.Fields {
		fields[field.Name] = field
	}

	for i, col := range info.Columns {
		field, ok := fields[col.Name]
		if !ok {
			continue
		}

		attrs := field2ColumnAttrs(&field)
		attrs.Order = 1000 + i

		switch col.Index {
		case -1:
			typeName := col.Type.Kind
			switch typeName {
			case types.KindL3Endpoint:
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
				addL3EndpointColumns(cols, col.Name, func(e *types.Event) eventtypes.L3Endpoint {
					if len(e.L3Endpoints) == 0 {
						return eventtypes.L3Endpoint{}
					}
					return e.L3Endpoints[index].L3Endpoint
				})
				l3endpointCounter++
			case types.KindL4Endpoint:
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
				addL4EndpointColumns(cols, col.Name, func(e *types.Event) eventtypes.L4Endpoint {
					if len(e.L4Endpoints) == 0 {
						return eventtypes.L4Endpoint{}
					}
					return e.L4Endpoints[index].L4Endpoint
				})
				l4endpointCounter++
			case types.KindTimestamp:
				// Take the value here, otherwise it'll use the wrong value after
				// it's increased
				index := timestampsCounter
				err := cols.AddColumn(attrs, func(e *types.Event) any {
					if len(e.Timestamps) == 0 {
						return ""
					}
					return e.Timestamps[index].String()
				})
				if err != nil {
					return nil, fmt.Errorf("adding timestamp column: %w", err)
				}
				timestampsCounter++
				continue

			}
		case 0:
			field := columns.DynamicField{
				Attributes: &attrs,
				Template:   attrs.Template,
				Type:       reflectTypeFromType(col.Type),
				Offset:     uintptr(col.Offset),
			}

			ebpfFields = append(ebpfFields, field)
		case 1:
			field := columns.DynamicField{
				Attributes: &attrs,
				Template:   attrs.Template,
				Type:       reflectTypeFromType(col.Type),
				Offset:     uintptr(col.Offset),
			}
			blobFields = append(blobFields, field)
		default:
			index := col.Index
			cols.AddColumn(attrs, func(e *types.Event) any {
				if e.Blob == nil {
					return ""
				}

				return string(e.Blob[index])
			})
		}
	}

	ebpfBase := func(ev *types.Event) unsafe.Pointer {
		return unsafe.Pointer(&ev.Blob[indexBPF][0])
	}
	if err := cols.AddFields(ebpfFields, ebpfBase); err != nil {
		return nil, fmt.Errorf("adding fields: %w", err)
	}

	blobBase := func(ev *types.Event) unsafe.Pointer {
		return unsafe.Pointer(&ev.Blob[indexFixed][0])
	}
	if err := cols.AddFields(blobFields, blobBase); err != nil {
		return nil, fmt.Errorf("adding blob fields: %w", err)
	}

	return cols, nil
}

func (g *GadgetDesc) CustomParser(info *types.GadgetInfo) (parser.Parser, error) {
	cols, err := g.getColumns(info)
	if err != nil {
		return nil, fmt.Errorf("getting columns: %w", err)
	}

	return parser.NewParser[types.Event](cols), nil
}

func (g *GadgetDesc) customJsonParser(info *types.GadgetInfo, options ...columns_json.Option) (*columns_json.Formatter[types.Event], error) {
	cols, err := g.getColumns(info)
	if err != nil {
		return nil, err
	}
	return columns_json.NewFormatter(cols.ColumnMap, options...), nil
}

func jsonConverterFn(formatter *columns_json.Formatter[types.Event], printer types.Printer) func(ev any) {
	return func(ev any) {
		switch typ := ev.(type) {
		case *types.Event:
			printer.Output(formatter.FormatEntry(typ))
		case []*types.Event:
			printer.Output(formatter.FormatEntries(typ))
		default:
			printer.Logf(logger.WarnLevel, "unknown type: %T", typ)
		}
	}
}

func (g *GadgetDesc) JSONConverter(info *types.GadgetInfo, printer types.Printer) func(ev any) {
	formatter, err := g.customJsonParser(info)
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return jsonConverterFn(formatter, printer)
}

func (g *GadgetDesc) JSONPrettyConverter(info *types.GadgetInfo, printer types.Printer) func(ev any) {
	formatter, err := g.customJsonParser(info, columns_json.WithPrettyPrint())
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return jsonConverterFn(formatter, printer)
}

func (g *GadgetDesc) YAMLConverter(info *types.GadgetInfo, printer types.Printer) func(ev any) {
	formatter, err := g.customJsonParser(info)
	if err != nil {
		printer.Logf(logger.WarnLevel, "creating json formatter: %s", err)
		return nil
	}
	return func(ev any) {
		var eventJson string
		switch typ := ev.(type) {
		case *types.Event:
			eventJson = formatter.FormatEntry(typ)
		case []*types.Event:
			eventJson = formatter.FormatEntries(typ)
		default:
			printer.Logf(logger.WarnLevel, "unknown type: %T", typ)
			return
		}

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

// functions to send columns from server to client
func typeFromBTF(typ btf.Type) *types.Type {
	switch typedMember := typ.(type) {
	case *btf.Array:
		arrType := simpleTypeFromBTF(typedMember.Type)
		if arrType == nil {
			return nil
		}
		return &types.Type{
			Kind:           types.KindArray,
			ArrayNElements: int(typedMember.Nelems),
			ArrayKind:      arrType.Kind,
		}
	default:
		return simpleTypeFromBTF(typ)
	}
}

func simpleTypeFromBTF(typ btf.Type) *types.Type {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return &types.Type{Kind: types.KindInt8}
			case 2:
				return &types.Type{Kind: types.KindInt16}
			case 4:
				return &types.Type{Kind: types.KindInt32}
			case 8:
				return &types.Type{Kind: types.KindInt64}
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return &types.Type{Kind: types.KindUint8}
			case 2:
				return &types.Type{Kind: types.KindUint16}
			case 4:
				return &types.Type{Kind: types.KindUint32}
			case 8:
				return &types.Type{Kind: types.KindUint64}
			}
		case btf.Bool:
			return &types.Type{Kind: types.KindBool}
		case btf.Char:
			return &types.Type{Kind: types.KindUint8}
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return &types.Type{Kind: types.KindFloat32}
		case 8:
			return &types.Type{Kind: types.KindFloat64}
		}
	case *btf.Typedef:
		typ, _ := getUnderlyingType(typedMember)
		return simpleTypeFromBTF(typ)
	}

	return nil
}

func calculateColumnsForClient(gadgetMetadata *types.GadgetMetadata, progContent []byte) ([]types.ColumnDesc, error) {
	eventType, err := getEventTypeBTF(progContent, gadgetMetadata)
	if err != nil {
		return nil, fmt.Errorf("getting value struct: %w", err)
	}

	colNames := map[string]struct{}{}

	eventStruct, ok := gadgetMetadata.Structs[eventType.Name]
	if !ok {
		return nil, fmt.Errorf("struct %s not found in gadget metadata", eventType.Name)
	}

	for _, field := range eventStruct.Fields {
		colNames[field.Name] = struct{}{}
	}

	columns := []types.ColumnDesc{}

	for _, member := range eventType.Members {
		member := member

		_, ok := colNames[member.Name]
		if !ok {
			continue
		}

		switch member.Type.TypeName() {
		case types.L3EndpointTypeName:
			col := types.ColumnDesc{
				Name:  member.Name,
				Index: indexVirtual,
				Type:  types.Type{Kind: types.KindL3Endpoint},
			}
			columns = append(columns, col)
			continue
		case types.L4EndpointTypeName:
			// Add the column that is enriched
			col := types.ColumnDesc{
				Name:  member.Name,
				Index: indexVirtual,
				Type:  types.Type{Kind: types.KindL4Endpoint},
			}
			columns = append(columns, col)
			continue
		case types.TimestampTypeName:
			col := types.ColumnDesc{
				Name:  member.Name,
				Index: indexVirtual,
				Type:  types.Type{Kind: types.KindTimestamp},
			}
			columns = append(columns, col)
			continue
		}

		rType := typeFromBTF(member.Type)
		if rType == nil {
			continue
		}

		col := types.ColumnDesc{
			Name:   member.Name,
			Type:   *rType,
			Offset: uintptr(member.Offset.Bytes()),
		}

		columns = append(columns, col)
	}

	return columns, nil
}
