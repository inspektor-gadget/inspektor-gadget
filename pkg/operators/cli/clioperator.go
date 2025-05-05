// Copyright 2024-2025 The Inspektor Gadget authors
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

package clioperator

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"golang.org/x/term"
	"sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	// Priority is set to a high value, since this operator is used as sink and so all changes to DataSources need
	// to have happened before the operator becomes active
	Priority = 10000

	ParamFields = "fields"
	ParamMode   = "output"

	ModeJSON       = "json"
	ModeJSONPretty = "jsonpretty"
	ModeColumns    = "columns"
	ModeYAML       = "yaml"
	ModeNone       = "none"
	ModeRaw        = "raw"

	DefaultOutputMode = ModeColumns

	// AnnotationClearScreenBefore can be used to clear the screen before printing a new event; usually used for
	// array events
	AnnotationClearScreenBefore = "cli.clear-screen-before"

	// AnnotationSupportedOutputModes can be used to specify the supported
	// output modes for a DataSource in a comma-separated list.
	AnnotationSupportedOutputModes = "cli.supported-output-modes"

	// AnnotationDefaultOutputMode can be used to specify the default output mode for a DataSource.
	AnnotationDefaultOutputMode = "cli.default-output-mode"
)

var DefaultSupportedOutputModes = []string{ModeColumns, ModeJSON, ModeJSONPretty, ModeNone, ModeYAML}

type cliOperator struct{}

func (o *cliOperator) Name() string {
	return "cli"
}

func (o *cliOperator) Init(params *params.Params) error {
	return nil
}

func (o *cliOperator) GlobalParams() api.Params {
	return nil
}

func (o *cliOperator) InstanceParams() api.Params {
	return nil
}

func (o *cliOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (operators.DataOperatorInstance, error) {
	op := &cliOperatorInstance{
		paramValues:          paramValues,
		supportedOutputModes: make(map[string][]string),
		defaultOutputMode:    make(map[string]string),
	}

	return op, nil
}

func (o *cliOperator) Priority() int {
	return Priority
}

type cliOperatorInstance struct {
	paramValues api.ParamValues
	// key: datasource name, value: supported output modes
	supportedOutputModes map[string][]string
	// key: datasource name, value: default output mode
	defaultOutputMode map[string]string
}

func (o *cliOperatorInstance) Name() string {
	return "cli"
}

func (o *cliOperatorInstance) InstanceParams() params.ParamDescs {
	return nil
}

func getNamesFromFields(fields []*api.Field) []string {
	res := make([]string, 0, len(fields))
	for _, f := range fields {
		res = append(res, f.FullName)
	}
	return res
}

func (o *cliOperatorInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	dataSources := gadgetCtx.GetDataSources()

	nameDS := len(dataSources) > 1

	// if we have multiple DataSources, we need to prefix the list of fields with the DataSource's name

	fieldsDefaultValues := make([]string, 0, len(dataSources))
	fieldsDescriptions := make([]string, 0, len(dataSources)+1)
	fieldsDescriptions = append(fieldsDescriptions, "Available data sources / fields")
	outputDescriptions := make([]string, 0, len(dataSources))
	outputDescriptions = append(outputDescriptions,
		`Specifies output mode for all ("mode1") or per data source ("datasource:mode1,datasource2:mode2")
  Supported data sources / output modes:`)
	outputDefaultValues := make([]string, 0, len(dataSources))
	for _, ds := range dataSources {
		// Fields
		fields := ds.Fields()
		availableFields := make([]*api.Field, 0, len(fields))
		defaultFields := make([]*api.Field, 0)
		for _, f := range fields {
			if datasource.FieldFlagUnreferenced.In(f.Flags) ||
				datasource.FieldFlagContainer.In(f.Flags) ||
				datasource.FieldFlagEmpty.In(f.Flags) {
				continue
			}
			availableFields = append(availableFields, f)
			if datasource.FieldFlagHidden.In(f.Flags) {
				continue
			}
			defaultFields = append(defaultFields, f)
		}

		// Sort available fields by name
		sort.Slice(availableFields, func(i, j int) bool {
			return availableFields[i].FullName < availableFields[j].FullName
		})

		// Sort default fields by order value
		sort.SliceStable(defaultFields, func(i, j int) bool {
			return defaultFields[i].Order < defaultFields[j].Order
		})

		fieldsDefaultValue := strings.Join(getNamesFromFields(defaultFields), ",")
		if nameDS {
			fieldsDefaultValue = ds.Name() + ":" + fieldsDefaultValue
		}

		fieldsDefaultValues = append(fieldsDefaultValues, fieldsDefaultValue)

		var sb strings.Builder
		fmt.Fprintf(&sb, "  %q (data source):\n", ds.Name())
		for _, f := range availableFields {
			fmt.Fprintf(&sb, "    %s\n", f.FullName)
			if desc, ok := f.Annotations[metadatav1.DescriptionAnnotation]; ok {
				fmt.Fprintf(&sb, "      %s\n", desc)
			}
			if oneOf, ok := f.Annotations[metadatav1.ValueOneOfAnnotation]; ok {
				fmt.Fprintf(&sb, "      One of: %s\n", oneOf)
			}
		}
		fieldsDescriptions = append(fieldsDescriptions, sb.String())

		// Supported output modes
		supportedOutputs := DefaultSupportedOutputModes
		if supportedOutputsAnnotated, ok := ds.Annotations()[AnnotationSupportedOutputModes]; ok {
			supportedOutputs = strings.Split(supportedOutputsAnnotated, ",")
		}
		sort.Strings(supportedOutputs)
		o.supportedOutputModes[ds.Name()] = supportedOutputs

		sb.Reset()
		fmt.Fprintf(&sb, "    %q (data source):\n", ds.Name())
		for _, mode := range supportedOutputs {
			fmt.Fprintf(&sb, "      %s\n", mode)
		}
		outputDescriptions = append(outputDescriptions, sb.String())

		// Default output mode
		defaultOutput := DefaultOutputMode
		if defaultOutputAnnotated, ok := ds.Annotations()[AnnotationDefaultOutputMode]; ok {
			if !slices.Contains(supportedOutputs, defaultOutputAnnotated) {
				// This shouldn't happen, it should be caught by the validation at compile time
				gadgetCtx.Logger().Warnf("default output mode %q for data source %q is not supported",
					defaultOutputAnnotated, ds.Name())
				continue
			}
			defaultOutput = defaultOutputAnnotated
		} else if !slices.Contains(supportedOutputs, DefaultOutputMode) {
			defaultOutput = supportedOutputs[0]
		}
		o.defaultOutputMode[ds.Name()] = defaultOutput
		if nameDS {
			defaultOutput = ds.Name() + ":" + defaultOutput
		}
		outputDefaultValues = append(outputDefaultValues, defaultOutput)
	}

	// --fields datasource:comma,separated,fields;datasource2:comma,separated,fields
	fields := &api.Param{
		Key:          ParamFields,
		DefaultValue: strings.Join(fieldsDefaultValues, ";"),
		Description:  strings.Join(fieldsDescriptions, "\n"),
	}

	mode := &api.Param{
		Key:          ParamMode,
		DefaultValue: strings.Join(outputDefaultValues, ","),
		Description:  strings.Join(outputDescriptions, "\n"),
		Alias:        "o",
	}

	return api.Params{fields, mode}
}

func parseFields(fieldsString string, defaultFields []string) []string {
	fields := strings.Split(fieldsString, ",")

	addedFields := make([]string, 0, len(fields))
	deletedFields := make([]string, 0, len(fields))
	explicitFields := make([]string, 0, len(fields))

	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		switch field[0] {
		case '+':
			addedFields = append(addedFields, field[1:])
		case '-':
			deletedFields = append(deletedFields, field[1:])
		default:
			if !slices.Contains(explicitFields, field) {
				explicitFields = append(explicitFields, field)
			}
		}
	}

	result := defaultFields
	if len(explicitFields) > 0 {
		result = explicitFields
	}

	for _, field := range addedFields {
		if !slices.Contains(result, field) {
			result = append(result, field)
		}
	}

	for _, field := range deletedFields {
		result = slices.DeleteFunc(result, func(s string) bool { return s == field })
	}
	return result
}

func (o *cliOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	params := apihelpers.ToParamDescs(o.ExtraParams(gadgetCtx)).ToParams()
	params.CopyFromMap(o.paramValues, "")

	fieldValues := strings.Split(params.Get(ParamFields).AsString(), ";")
	fieldLookup := make(map[string]string)
	for _, v := range fieldValues {
		dsFieldValues := strings.SplitN(v, ":", 2)
		var dsName string
		dsFields := dsFieldValues[0]
		if len(dsFieldValues) == 2 {
			dsName = dsFieldValues[0]
			dsFields = dsFieldValues[1]
		}
		fieldLookup[dsName] = dsFields
	}

	modes, err := apihelpers.GetStringValuesPerDataSource(params.Get(ParamMode).AsString())
	if err != nil {
		return fmt.Errorf("parsing default output modes: %w", err)
	}

	for _, ds := range gadgetCtx.GetDataSources() {
		gadgetCtx.Logger().Debugf("subscribing to %s", ds.Name())

		fields, hasFields := fieldLookup[ds.Name()]
		if !hasFields {
			fields, hasFields = fieldLookup[""] // fall back to default
		}

		mode, ok := modes[ds.Name()]
		if !ok {
			mode, ok = modes[""]
			if !ok {
				// Users may specify the mode for one data source and not for
				// another. In this case, we fall back to the default output
				// mode for the ones that are not specified.
				mode = o.defaultOutputMode[ds.Name()]
			}
		}

		if !slices.Contains(o.supportedOutputModes[ds.Name()], mode) {
			gadgetCtx.Logger().Warnf("output mode %q for data source %q is not supported; skipping data source",
				mode, ds.Name())
			continue
		}

		clearScreenBefore := ds.Annotations()[AnnotationClearScreenBefore] == "true"
		isTerminal := term.IsTerminal(int(os.Stdout.Fd()))

		switch mode {
		default:
			before := func() {}
			if clearScreenBefore && isTerminal {
				before = clearScreen
			}
			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				before()
				defaultDataFn(ds, data, os.Stdout)
				return nil
			}, Priority)
		case ModeNone:
			// Do nothing.
		case ModeColumns:
			p, err := ds.Parser()
			if err != nil {
				gadgetCtx.Logger().Warnf("failed to get parser: %v; skipping data source %q", err, ds.Name())
				continue
			}

			defCols := p.GetDefaultColumns()
			gadgetCtx.Logger().Debugf("default fields: %s", defCols)
			formatter := p.GetTextColumnsFormatter()

			if hasFields {
				parsedFields := parseFields(fields, defCols)
				err = formatter.SetShowColumns(parsedFields)
				if err != nil {
					gadgetCtx.Logger().Warnf("failed to set fields: %v; skipping data source %q", err, ds.Name())
					continue
				}
			}

			formatter.SetEventCallback(func(s string) {
				fmt.Println(s)
			})

			printHeader := func() {
				fmt.Println(formatter.FormatHeader())
			}

			headerFuncs := []func(){}
			if clearScreenBefore && isTerminal {
				headerFuncs = append(headerFuncs, clearScreen)
			}
			headerFuncs = append(headerFuncs, printHeader)

			switch ds.Type() {
			case datasource.TypeSingle:
				printHeader()
				p.SetEventCallback(formatter.EventHandlerFunc())
				handler, ok := p.EventHandlerFunc().(func(data *datasource.DataTuple))
				if !ok {
					gadgetCtx.Logger().Warnf("invalid data format: expected func(data *datasource.DataTuple), got %T; skipping data source %q",
						p.EventHandlerFunc(), ds.Name())
					continue
				}
				ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
					handler(datasource.NewDataTuple(ds, data))
					return nil
				}, Priority)

			case datasource.TypeArray:
				// print the header before only for gadgets that will clean the
				// screen later on, otherwise it could be printed multiple
				// times.
				if clearScreenBefore {
					printHeader()
				}
				p.SetEventCallback(formatter.EventHandlerFuncArray(headerFuncs...))
				handler, ok := p.EventHandlerFuncArray().(func(data []*datasource.DataTuple))
				if !ok {
					gadgetCtx.Logger().Warnf("invalid data format: expected func(data []*datasource.DataTuple), got %T; skipping data source %q",
						p.EventHandlerFunc(), ds.Name())
					continue
				}

				ds.SubscribeArray(func(ds datasource.DataSource, dataArray datasource.DataArray) error {
					l := dataArray.Len()
					tuples := make([]*datasource.DataTuple, 0, l)

					for i := 0; i < l; i++ {
						data := dataArray.Get(i)
						tuples = append(tuples, datasource.NewDataTuple(ds, data))
					}

					handler(tuples)
					return nil
				}, Priority)
			}
		case ModeJSON, ModeJSONPretty, ModeYAML:
			// var opts []json.Option
			// if hasFields {
			// 	opts = append(opts, json.WithFields(strings.Split(fields, ",")))
			// }

			jsonFormatter, err := json.New(ds,
				// TODO: compatibility for now: add all; remove me later on and use the commented version above
				json.WithShowAll(true),
				json.WithPretty(mode == ModeJSONPretty, "  "),
				json.WithArray(ds.Type() == datasource.TypeArray),
			)
			if err != nil {
				gadgetCtx.Logger().Warnf("failed to initialize JSON formatter: %v; skipping data source %q", err, ds.Name())
				continue
			}

			if mode == ModeYAML {
				// For the time being, this uses a slow approach to marshal to YAML, by first
				// converting to JSON and then to YAML. This should get a dedicated formatter sooner or later.
				ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
					return yamlDataFn(ds, data, jsonFormatter, os.Stdout)
				}, Priority)
				continue
			}

			switch ds.Type() {
			case datasource.TypeSingle:
				ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
					jsonSingleDataFn(ds, data, jsonFormatter, os.Stdout)
					return nil
				}, Priority)
			case datasource.TypeArray:
				ds.SubscribeArray(func(ds datasource.DataSource, dataArray datasource.DataArray) error {
					jsonArrayDataFn(ds, dataArray, jsonFormatter, os.Stdout)
					return nil
				}, Priority)
			}
		}

	}
	return nil
}

func defaultDataFn(ds datasource.DataSource, data datasource.Data, w io.Writer) {
	for _, f := range ds.Accessors(false) {
		if s, err := f.String(data); err == nil {
			fmt.Fprint(w, s)
		}
	}
}

func yamlDataFn(ds datasource.DataSource, data datasource.Data, jsonFormatter *json.Formatter, w io.Writer) error {
	yml, err := yaml.JSONToYAML(jsonFormatter.Marshal(data))
	if err != nil {
		return fmt.Errorf("serializing yaml: %w", err)
	}
	fmt.Fprintln(w, "---")
	fmt.Fprint(w, string(yml))
	return nil
}

func jsonSingleDataFn(ds datasource.DataSource, data datasource.Data, jsonFormatter *json.Formatter, w io.Writer) {
	fmt.Fprintln(w, string(jsonFormatter.Marshal(data)))
}

func jsonArrayDataFn(ds datasource.DataSource, dataArray datasource.DataArray, jsonFormatter *json.Formatter, w io.Writer) {
	fmt.Fprintln(w, string(jsonFormatter.MarshalArray(dataArray)))
}

func (o *cliOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *cliOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

var CLIOperator = &cliOperator{}
