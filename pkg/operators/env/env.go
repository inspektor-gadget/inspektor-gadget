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

package env

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	Name     = "env"
	Priority = 1

	AnnotationPrefix = "env.fields."

	ParamEnvVars = "env-vars"
)

type Config struct {
	AllowedVars []string
}

type envOperator struct {
	config Config
}

func (e *envOperator) Name() string {
	return Name
}

func (e *envOperator) Init(params *params.Params) error {
	e.config.AllowedVars = strings.Split(params.Get(ParamEnvVars).AsString(), ",")
	return nil
}

func (e *envOperator) GlobalParams() api.Params {
	return api.Params{
		{
			Key:         "env-vars",
			Description: "Comma-separated list of environment variables to allow to be included",
			Title:       "Allowed Environment Variables",
		},
	}
}

func (e *envOperator) InstanceParams() api.Params {
	return nil
}

func (e *envOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	instance := &envOperatorInstance{
		op:     e,
		fields: make(map[datasource.DataSource][]datasource.DataFunc),
	}
	err := instance.init(gadgetCtx)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (e *envOperator) Priority() int {
	return Priority
}

type envOperatorInstance struct {
	op     *envOperator
	fields map[datasource.DataSource][]datasource.DataFunc
}

func (e *envOperatorInstance) Name() string {
	return Name
}

func (e *envOperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	e.fields = make(map[datasource.DataSource][]datasource.DataFunc)
	for _, ds := range gadgetCtx.GetDataSources() {
		annotations := ds.Annotations()
		for k, v := range annotations {
			fieldName, ok := strings.CutPrefix(k, AnnotationPrefix)
			if !ok {
				continue
			}

			// check, if the environment variable is allowed
			if !slices.Contains(e.op.config.AllowedVars, v) {
				return fmt.Errorf("environment var %q not in allowed vars: %v", fieldName, e.op.config.AllowedVars)
			}

			nf, err := ds.AddField(fieldName, api.Kind_String)
			if err != nil {
				return fmt.Errorf("adding field %s: %w", fieldName, err)
			}

			ct := os.Getenv(v)

			gadgetCtx.Logger().Debugf("adding field %s with content %q from environment variable %q", fieldName, ct, v)
			e.fields[ds] = append(e.fields[ds], func(ds datasource.DataSource, data datasource.Data) error {
				return nf.PutString(data, ct)
			})
		}
	}
	return nil
}

func (e *envOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, funcs := range e.fields {
		for _, f := range funcs {
			err := ds.Subscribe(f, 0)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *envOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (e *envOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func init() {
	operators.RegisterDataOperator(&envOperator{})
}
