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
	"strings"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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

	genType, ok := instanceParamValues[ParamType]
	if ok {
		switch genType {
		case eventgenerator.DNSGeneratorType:
			eop.generator = eventgenerator.NewDNSGenerator()
		default:
			return nil, fmt.Errorf("unknown generator type %q", genType)
		}
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

func (e *eventGeneratorOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	//iter, err := strconv.Atoi(e.params[ParamIterations])
	//if err != nil {
	//	return fmt.Errorf("parsing iterations: %w", err)
	//}

	cc := &containercollection.ContainerCollection{}
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithContainerFanotifyEbpf(),
		containercollection.WithMultipleContainerRuntimesEnrichment(
			[]*containerutilsTypes.RuntimeConfig{
				{Name: types.RuntimeNameDocker},
				{Name: types.RuntimeNameContainerd},
			}),
	}
	if err := cc.Initialize(opts...); err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}
	defer cc.Close()

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

	container, ok := e.params[ParamTargetContainer]
	if !ok {
		return fmt.Errorf("target container is required")
	}
	cs := &containercollection.ContainerSelector{
		Runtime: containercollection.RuntimeSelector{
			ContainerName: container,
		},
	}
	cc.ContainerRangeWithSelector(cs, func(c *containercollection.Container) {
		err := e.generator.Generate(*c, gparam)
		if err != nil {
			gadgetCtx.Logger().Warnf("failed to generate event: %v", err)
		}
	})

	return nil
}

func (e *eventGeneratorOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return e.generator.Cleanup()
}

func init() {
	operators.RegisterDataOperator(&eventGeneratorOperator{})
}
