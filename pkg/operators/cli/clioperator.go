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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type cliOperator struct{}

func (o *cliOperator) Name() string {
	return "cliOperator"
}

func (o *cliOperator) Init(params *params.Params) error {
	return nil
}

func (o *cliOperator) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (o *cliOperator) InstantiateDataOperator(ctx operators.GadgetContext) (operators.DataOperatorInstance, error) {
	return &cliOperatorInstance{}, nil
}

type cliOperatorInstance struct{}

func (c *cliOperatorInstance) Name() string {
	return "cliOperatorInstance"
}

func (c *cliOperatorInstance) Prepare(ctx operators.GadgetContext) error {
	ctx.RegisterParam(&api.Param{
		Key:          "output-mode",
		DefaultValue: "columns",
	})
	return nil
}

func (c *cliOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	for _, ds := range gadgetCtx.GetDataSources() {
		gadgetCtx.Logger().Debugf("subscribing to %s", ds.Name())

		p, err := ds.Parser()
		if err != nil {
			gadgetCtx.Logger().Debugf("failed to get parser: %w", err)
			continue
		}

		defCols := p.GetDefaultColumns()
		gadgetCtx.Logger().Debugf("default columns: %s", defCols)
		formatter := p.GetTextColumnsFormatter()

		// xformatter := json.NewFormatter[datasource.DataTuple](p.GetColumns().(columns.Columns[datasource.DataTuple]).GetColumnMap())
		// p.SetEventCallback(xformatter.FormatEntries)

		fmt.Printf("%s\n", formatter.FormatHeader())

		formatter.SetEventCallback(func(s string) {
			fmt.Printf("%s\n", s)
		})

		p.SetEventCallback(formatter.EventHandlerFunc())
		handler, ok := p.EventHandlerFunc().(func(data *datasource.DataTuple))
		if !ok {
			gadgetCtx.Logger().Warnf("invalid data format")
			continue
		}

		if !ok {
			gadgetCtx.Logger().Debugf("failed to get parser func: %w", err)
			continue
		}

		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			t := datasource.NewDataTuple(ds, data)
			handler(t)
			return nil
		}, 10000)
	}

	return nil
}

func init() {
	operators.RegisterOperator(&cliOperator{})
}
