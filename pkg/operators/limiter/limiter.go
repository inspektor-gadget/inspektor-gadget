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

// Package limiter is a data operator that limits the number of entries in each
// batch of data. This operator is only enabled for data sources of type array.
// A great scenario for this operator is when you are already sorting data
// within an array of data and you want to filter out the top `X` entries.
package limiter

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name            = "limiter"
	ParamMaxEntries = "max-entries"
	Priority        = 9600
)

type limiterOperator struct{}

func (l *limiterOperator) Name() string {
	return name
}

func (l *limiterOperator) Init(params *params.Params) error {
	return nil
}

func (l *limiterOperator) GlobalParams() api.Params {
	return nil
}

func (l *limiterOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:   ParamMaxEntries,
			Title: "Max Entries",
			Description: "The maximum number of entries for each batch of data. " +
				"If using multiple array data sources, prefix the value with 'datasourcename:' and separate with ','. " +
				"If no data source is specified, the value will be applied to all array data sources." +
				"Use -1 to disable the limiter.",
			DefaultValue: "-1",
			TypeHint:     api.TypeString,
		},
	}
}

func (l *limiterOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	// When getting the GadgetInfo, InstantiateDataOperator is called with an
	// empty instanceParamValues. In such cases, we don't need to validate the
	// ParamMaxEntries parameter, but just return an instance if there is, at
	// least, one array data source; otherwise return nil (disabling the
	// operator).
	maxEntries, ok := instanceParamValues[ParamMaxEntries]
	if !ok {
		for _, ds := range gadgetCtx.GetDataSources() {
			if ds.Type() == datasource.TypeArray {
				return &limiterOperatorInstance{}, nil
			}
		}
		return nil, nil
	}

	// If ParamMaxEntries is set, it must be valid.
	valuesPerDs, err := apihelpers.GetIntValuesPerDataSource(maxEntries)
	if err != nil {
		return nil, fmt.Errorf("parsing %s (%q): %w", ParamMaxEntries, maxEntries, err)
	}
	if len(valuesPerDs) == 0 {
		return nil, fmt.Errorf("missing value for %s", ParamMaxEntries)
	}

	maxEntriesPerDs := make(map[datasource.DataSource]int)
	for _, ds := range gadgetCtx.GetDataSources() {
		var maxEntries int
		if val, ok := valuesPerDs[""]; ok {
			if ds.Type() != datasource.TypeArray {
				continue
			}
			// Disable for all data sources
			if val == -1 {
				return nil, nil
			}
			maxEntries = val
		} else if val, ok := valuesPerDs[ds.Name()]; ok {
			if ds.Type() != datasource.TypeArray {
				return nil, fmt.Errorf("%s can only be used on array data sources", ParamMaxEntries)
			}
			// Disable for this specific data source
			if val == -1 {
				continue
			}
			maxEntries = val
		}

		if maxEntries < -1 {
			return nil, fmt.Errorf("invalid value for %s: %d", ParamMaxEntries, maxEntries)
		}
		maxEntriesPerDs[ds] = maxEntries
	}

	if len(maxEntriesPerDs) == 0 {
		gadgetCtx.Logger().Infof("limiter: no array data sources need to be limited. Skipping operator")
		return nil, nil
	}

	return &limiterOperatorInstance{
		maxEntries: maxEntriesPerDs,
	}, nil
}

func (l *limiterOperator) Priority() int {
	return Priority
}

type limiterOperatorInstance struct {
	maxEntries map[datasource.DataSource]int
}

func (l *limiterOperatorInstance) Name() string {
	return name
}

func (l *limiterOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, maxEntries := range l.maxEntries {
		ds.SubscribeArray(func(ds datasource.DataSource, data datasource.DataArray) error {
			if data.Len() <= maxEntries {
				return nil
			}
			if err := data.Resize(maxEntries); err != nil {
				return fmt.Errorf("limiting data source %q to %d entries: %w", ds.Name(), maxEntries, err)
			}
			return nil
		}, Priority)
	}
	return nil
}

func (l *limiterOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (l *limiterOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (l *limiterOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

var Operator = &limiterOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
