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

package clioperator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	// Priority is set to a high value, since this operator is used as sink and so all changes to DataSources need
	// to have happened before the operator becomes active
	Priority = 10000

	ParamFields = "fields"
	ParamMode   = "output"

	ModeJSON    = "json"
	ModeColumns = "columns"
)

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
		mode:        ModeColumns,
		paramValues: paramValues,
	}

	return op, nil
}

func (o *cliOperator) Priority() int {
	return Priority
}

type cliOperatorInstance struct {
	mode        string
	paramValues api.ParamValues
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

	nameDS := false

	// if we have multiple DataSources, we need to prefix the list of fields with the DataSource's name
	if len(dataSources) > 1 {
		nameDS = true
	}

	fieldsDefaultValues := make([]string, 0, len(dataSources))
	fieldsDescriptions := make([]string, 0, len(dataSources)+1)
	fieldsDescriptions = append(fieldsDescriptions, "Available data sources / fields")
	for _, ds := range dataSources {
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
			if desc, ok := f.Annotations["description"]; ok { // TODO: const to API?
				fmt.Fprintf(&sb, "      %s\n", desc)
			}
		}
		fieldsDescriptions = append(fieldsDescriptions, sb.String())
	}

	// --fields datasource:comma,separated,fields;datasource2:comma,separated,fields
	fields := &api.Param{
		Key:          ParamFields,
		DefaultValue: strings.Join(fieldsDefaultValues, ";"),
		Description:  strings.Join(fieldsDescriptions, "\n"),
	}

	mode := &api.Param{
		Key:            ParamMode,
		DefaultValue:   ModeColumns,
		Description:    "output mode",
		Alias:          "o",
		PossibleValues: []string{ModeJSON, ModeColumns},
	}

	return api.Params{fields, mode}
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

	o.mode = params.Get(ParamMode).AsString()

	for _, ds := range gadgetCtx.GetDataSources() {
		gadgetCtx.Logger().Debugf("subscribing to %s", ds.Name())

		fields, hasFields := fieldLookup[ds.Name()]
		if !hasFields {
			fields, hasFields = fieldLookup[""] // fall back to default
		}

		switch o.mode {
		case ModeColumns:
			p, err := ds.Parser()
			if err != nil {
				gadgetCtx.Logger().Debugf("failed to get parser: %v", err)
				continue
			}

			defCols := p.GetDefaultColumns()
			gadgetCtx.Logger().Debugf("default fields: %s", defCols)
			formatter := p.GetTextColumnsFormatter()

			if hasFields {
				err := formatter.SetShowColumns(strings.Split(fields, ","))
				if err != nil {
					return fmt.Errorf("setting fields: %w", err)
				}
			}

			formatter.SetEventCallback(func(s string) {
				fmt.Print(s)
				fmt.Print("\n")
			})

			p.SetEventCallback(formatter.EventHandlerFunc())
			handler, ok := p.EventHandlerFunc().(func(data *datasource.DataTuple))
			if !ok {
				gadgetCtx.Logger().Warnf("invalid data format: expected func(data *datasource.DataTuple), got %T",
					p.EventHandlerFunc())
				continue
			}

			fmt.Println(formatter.FormatHeader())

			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				handler(datasource.NewDataTuple(ds, data))
				return nil
			}, Priority)
		case ModeJSON:
			var opts []json.Option
			// if hasFields {
			// 	opts = append(opts, json.WithFields(strings.Split(fields, ",")))
			// }

			// TODO: compatiblity for now: add all; remove me later on and use the commented version above
			opts = []json.Option{json.WithShowAll(true)}

			jsonFormatter, err := json.New(ds, opts...)
			if err != nil {
				return fmt.Errorf("initializing JSON formatter: %w", err)
			}

			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				fmt.Println(string(jsonFormatter.Marshal(data)))
				return nil
			}, Priority)
		}
	}
	return nil
}

func (o *cliOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *cliOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

var CLIOperator = &cliOperator{}
