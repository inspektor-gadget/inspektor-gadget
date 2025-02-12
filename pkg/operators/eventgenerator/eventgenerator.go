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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"strings"
)

const (
	priority             = 0
	name                 = "event-generator"
	ParamEnable          = "event-generator-enable"
	ParamType            = "event-generator-type"
	ParamIterations      = "event-generator-iterations"
	ParamTargetPod       = "event-generator-target-pod"
	ParamTargetNamespace = "event-generator-target-namespace"
	ParamTargetContainer = "event-generator-target-container"
	ParamParams          = "event-generator-params"
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
			PossibleValues: []string{eventgenerator.DNSGeneratorType},
		},
		{
			Key:          ParamIterations,
			Description:  "Number of iterations to run the generator",
			TypeHint:     api.TypeInt,
			DefaultValue: "-1",
		},
		{
			Key:         ParamParams,
			Description: "Comma-separated list of key-value pairs for a generator e.g domain:example.com,query-type:A",
			TypeHint:    api.TypeString,
		},
		{
			Key:         ParamTargetPod,
			Description: "Target pod for the event generator",
			TypeHint:    api.TypeString,
		},
		{
			Key:         ParamTargetNamespace,
			Description: "Target namespace for the event generator",
			TypeHint:    api.TypeString,
		},
		{
			Key:         ParamTargetContainer,
			Description: "Target container for the event generator",
			TypeHint:    api.TypeString,
		},
	}
}

func (e *eventGeneratorOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if !e.enabled {
		return nil, nil
	}

	eop := &eventGeneratorOperatorInstance{
		params: instanceParamValues,
	}

	return eop, nil
}

func (e *eventGeneratorOperator) Priority() int {
	return priority
}

type eventGeneratorOperatorInstance struct {
	generator eventgenerator.Generator
	params    map[string]string
}

func (e *eventGeneratorOperatorInstance) Name() string {
	return name
}

func (e *eventGeneratorOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	genType, ok := e.params[ParamType]
	if !ok {
		return fmt.Errorf("event generator type is required")
	}
	switch genType {
	case eventgenerator.DNSGeneratorType:
		e.generator = eventgenerator.NewDNSGenerator()
	default:
		return fmt.Errorf("unknown generator type %q", genType)
	}

	gparam := make(map[string]string)
	for _, p := range strings.Split(e.params[ParamParams], ",") {
		if p != "" {
			kv := strings.Split(p, ":")
			if len(kv) != 2 {
				return fmt.Errorf("failed to parse %s %q", ParamParams, kv)
			}
			gparam[kv[0]] = kv[1]
		}
	}

	found := false
	for _, ds := range gadgetCtx.GetDataSources() {
		if ds.Name() != "containers" {
			continue
		}
		found = true
		gadgetCtx.Logger().Debugf("event-generator: Subscribing to %s data source", ds.Name())

		eventField := ds.GetField("event_type")
		pidField := ds.GetField("pid")

		// Subscription to the containers data source must happen in PreStart
		// because the data source will start emitting events on the Start call
		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			event, err := eventField.String(data)
			if err != nil {
				return fmt.Errorf("failed to get event type: %w", err)
			}

			switch event {
			case "CREATED":
				pid, err := pidField.Uint32(data)
				if err != nil {
					return fmt.Errorf("failed to get containerPid: %w", err)
				}

				gadgetCtx.Logger().Debugf("event-generator: Starting %s generator for containerPid %d with params %v",
					e.generator.Name(), pid, gparam)

				err = e.generator.Generate(int(pid), gparam)
				if err != nil {
					gadgetCtx.Logger().Warnf("failed to generate event: %v", err)
				}
			case "DELETED":
				gadgetCtx.Logger().Debugf("event-generator: Stopping %s generator", e.generator.Name())
				e.generator.Cleanup()
			default:
				return fmt.Errorf("unknown event type %q", event)
			}

			return nil
		}, priority)
	}
	if !found {
		return fmt.Errorf("event-generator: no containers data source found")
	}
	return nil
}

func (e *eventGeneratorOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (e *eventGeneratorOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return e.generator.Cleanup()
}

func init() {
	operators.RegisterDataOperator(&eventGeneratorOperator{})
}
