// Copyright 2025 The Inspektor Gadget authors
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

package eventgenerator

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/event-generators/dns"

	generators "github.com/inspektor-gadget/inspektor-gadget/pkg/event-generators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	priority = 0

	name = "event-generator"

	// Global parameter keys
	ParamEnable = "event-generator-enable"

	// Instance parameter keys
	ParamType        = "event-generator-type"
	ParamCount       = "event-generator-count"
	ParamInterval    = "event-generator-interval"
	ParamEnvironment = "event-generator-environment"
	ParamParams      = "event-generator-params"
)

type eventGeneratorOperator struct {
	enabled bool
}

func (e *eventGeneratorOperator) Name() string {
	return name
}

func (e *eventGeneratorOperator) Init(globalParams *params.Params) error {
	e.enabled = globalParams.Get(ParamEnable).AsBool()
	return nil
}

func (e *eventGeneratorOperator) GlobalParams() api.Params {
	return api.Params{
		{
			Key:          ParamEnable,
			Description:  "Enable Event Generator",
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
		},
	}
}

func (e *eventGeneratorOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:            ParamType,
			Description:    "Event Generator Type",
			TypeHint:       api.TypeString,
			PossibleValues: generators.Generators(),
		},
		{
			Key:          ParamCount,
			Description:  "Number of iterations to run the generator. Use -1 for infinite",
			TypeHint:     api.TypeInt,
			DefaultValue: "-1",
		},
		{
			Key:          ParamInterval,
			Description:  "Interval between events",
			TypeHint:     api.TypeDuration,
			DefaultValue: "1s",
		},
		{
			Key:            ParamEnvironment,
			Description:    "Environment where the generator will run",
			TypeHint:       api.TypeString,
			DefaultValue:   generators.EnvHost.String(),
			PossibleValues: generators.Environments(),
		},
		{
			Key:         ParamParams,
			Description: "Comma-separated list of key-value pairs for a generator",
			TypeHint:    api.TypeString,
		},
	}
}

func (e *eventGeneratorOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if !e.enabled {
		return nil, nil
	}

	eop := &eventGeneratorOperatorInstance{}

	if genType, ok := instanceParamValues[ParamType]; ok && genType != "" {
		count, err := strconv.Atoi(instanceParamValues[ParamCount])
		if err != nil {
			return nil, fmt.Errorf("parsing count: %w", err)
		}

		interval, err := time.ParseDuration(instanceParamValues[ParamInterval])
		if err != nil {
			return nil, fmt.Errorf("parsing duration: %w", err)
		}

		gparams := make(map[string]string)
		for _, p := range strings.Split(instanceParamValues[ParamParams], ",") {
			if p != "" {
				kv := strings.Split(p, ":")
				if len(kv) != 2 {
					return nil, fmt.Errorf("failed to parse %s %q", ParamParams, kv)
				}
				gparams[kv[0]] = kv[1]
			}
		}

		eop.generator, err = generators.New(
			genType,
			gadgetCtx.Logger(),
			instanceParamValues[ParamEnvironment],
			count,
			interval,
			gparams,
		)
		if err != nil {
			return nil, fmt.Errorf("creating event generator of type %q: %w", genType, err)
		}
		gadgetCtx.Logger().Debugf("using event generator of type %q", genType)
	}

	return eop, nil
}

func (e *eventGeneratorOperator) Priority() int {
	return priority
}

type eventGeneratorOperatorInstance struct {
	generator generators.Generator
}

func (e *eventGeneratorOperatorInstance) Name() string {
	return name
}

func (e *eventGeneratorOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	err := e.generator.Generate()
	if err != nil {
		return fmt.Errorf("starting event generation: %w", err)
	}

	return nil
}

func (e *eventGeneratorOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return e.generator.Cleanup()
}

func init() {
	operators.RegisterDataOperator(&eventGeneratorOperator{})
}
