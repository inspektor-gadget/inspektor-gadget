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

package cutter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name         = "cutter"
	ParamMaxRows = "max-rows"
	Priority     = 9600
)

type cutterOperator struct{}

func (s *cutterOperator) Name() string {
	return name
}

func (s *cutterOperator) Init(params *params.Params) error {
	return nil
}

func (s *cutterOperator) GlobalParams() api.Params {
	return nil
}

func (s *cutterOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:   ParamMaxRows,
			Title: "Max Rows",
			Description: "The maximal number of rows to keep for each batch of data. " +
				"If using multiple data sources, prefix the value with 'datasourcename:' and separate with ';'",
		},
	}
}

func (s *cutterOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	dsCutters := make(map[string]int)
	for _, srt := range strings.Split(instanceParamValues[ParamMaxRows], ";") {
		dsMaxRows := strings.Split(srt, ":")
		dsName := ""
		maxRowsStr := dsMaxRows[0]
		if len(dsMaxRows) == 2 {
			dsName = dsMaxRows[0]
			maxRowsStr = dsMaxRows[1]
		}
		maxRows, err := strconv.Atoi(maxRowsStr)
		if err != nil {
			return nil, fmt.Errorf("parsing max-rows (%q): %w", maxRowsStr, err)
		}
		dsCutters[dsName] = maxRows
	}
	if len(dsCutters) == 0 {
		return nil, nil
	}

	// Check edge cases
	dsSpecific := true
	if _, ok := dsCutters[""]; ok {
		if len(dsCutters) > 1 {
			return nil, fmt.Errorf("mixing max-rows rules with and without specifying data source")
		}
		dsSpecific = false
	}

	cutters := make(map[datasource.DataSource]int)
	for _, ds := range gadgetCtx.GetDataSources() {
		maxRows := dsCutters[ds.Name()]
		if !dsSpecific {
			maxRows = dsCutters[""]
		}

		if maxRows == 0 {
			continue
		}

		if ds.Type() != datasource.TypeArray {
			return nil, fmt.Errorf("max-rows can only be used on array data sources")
		}

		cutters[ds] = maxRows
	}

	return &cutterOperatorInstance{
		cutters: cutters,
	}, nil
}

func (s *cutterOperator) Priority() int {
	return Priority
}

type cutterOperatorInstance struct {
	cutters map[datasource.DataSource]int
}

func (s *cutterOperatorInstance) Name() string {
	return name
}

func (s *cutterOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, maxRows := range s.cutters {
		ds.SubscribeArray(func(ds datasource.DataSource, data datasource.DataArray) error {
			if data.Len() <= maxRows {
				return nil
			}

			// TODO: Cut the data
			return nil
		}, Priority)
	}
	return nil
}

func (s *cutterOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (s *cutterOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

var Operator = &cutterOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
