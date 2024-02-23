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
	"log"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

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

func createPanel(ds datasource.DataSource, gadgetCtx operators.GadgetContext, app *tview.Application) (tview.Primitive, error) {
	tv := tview.NewTextView()

	//	tv.SetBorder(true)
	//	tv.SetTitle(ds.Name())
	tv.SetScrollable(false)
	tv.SetChangedFunc(func() {
		tv.ScrollToEnd()
		app.Draw()
	})

	frame := tview.NewFrame(tv)
	frame.SetBorder(true)
	frame.SetTitle(ds.Name())
	frame.SetBorders(0, 0, 0, 0, 0, 0)

	p, err := ds.Parser()
	if err != nil {
		return nil, fmt.Errorf("failed to get parser: %w", err)
	}

	defCols := p.GetDefaultColumns()
	gadgetCtx.Logger().Debugf("default columns: %s", defCols)
	formatter := p.GetTextColumnsFormatter()

	// TODO: hack to trim the size by two that are consumed by the border
	trim := func(s string) string {
		return s[:len(s)-2] + "\n"
	}

	header := formatter.FormatHeader()
	frame.AddText(trim(header), true, tview.AlignCenter, tcell.ColorBlue)
	//tv.Write([]byte(trim(header)))

	formatter.SetEventCallback(func(s string) {
		tv.Write([]byte(trim(s)))
	})

	p.SetEventCallback(formatter.EventHandlerFunc())
	handler, ok := p.EventHandlerFunc().(func(data *datasource.DataTuple))
	if !ok {
		return nil, fmt.Errorf("invalid data format")
	}

	//if !ok {
	//	return nil, fmt.Errorf("failed to get parser func: %w", err)
	//}

	ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
		t := datasource.NewDataTuple(ds, data)
		handler(t)
		return nil
	}, 10000)

	return frame, nil
}

func (c *cliOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	app := tview.NewApplication()
	flex := tview.NewFlex()
	flex.SetDirection(tview.FlexRow)

	for _, ds := range gadgetCtx.GetDataSources() {
		gadgetCtx.Logger().Debugf("subscribing to %s", ds.Name())
		tv, err := createPanel(ds, gadgetCtx, app)
		if err != nil {
			gadgetCtx.Logger().Warn("creating tv: %v", err)
			continue
		}

		flex.AddItem(tv, 0, 1, false)
	}

	go func() {
		<-gadgetCtx.Context().Done()
		app.Stop()
	}()

	go func() {
		// Set the flex layout as the root of the application
		if err := app.SetRoot(flex, true).Run(); err != nil {
			log.Fatal(err)
		}
	}()

	return nil
}

func init() {
	operators.RegisterOperator(&cliOperator{})
}
