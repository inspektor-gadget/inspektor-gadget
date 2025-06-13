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
	"slices"
	"strconv"
	"strings"
	"time"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/event-generators/dns"
	"github.com/spf13/viper"

	generators "github.com/inspektor-gadget/inspektor-gadget/pkg/event-generators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	priority = 0

	name = "event-generator"

	// Global parameter keys
	ParamEnable              = "event-generator-enable"
	ParamAllowedGenerators   = "allowed-generators"
	ParamAllowedEnvironments = "allowed-environments"

	// Instance parameter keys
	ParamType        = "event-generator-type"
	ParamCount       = "event-generator-count"
	ParamInterval    = "event-generator-interval"
	ParamEnvironment = "event-generator-environment"
	ParamParams      = "event-generator-params"
)

type eventGeneratorOperator struct {
	enabled             bool
	allowedGenerators   []string
	allowedEnvironments []string
}

func (e *eventGeneratorOperator) Name() string {
	return name
}

func (e *eventGeneratorOperator) GlobalParams() api.Params {
	return api.Params{
		{
			Key:          ParamEnable,
			Description:  "Enable Event Generator",
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
		},
		{
			Key:            ParamAllowedGenerators,
			Description:    "Comma-separated list of allowed event generators. By default none are allowed.",
			DefaultValue:   "",
			TypeHint:       api.TypeString,
			PossibleValues: generators.Generators(),
		},
		{
			Key:            ParamAllowedEnvironments,
			Description:    "Comma-separated list of allowed environments. By default none are allowed.",
			DefaultValue:   "",
			TypeHint:       api.TypeString,
			PossibleValues: generators.Environments(),
		},
	}
}

func (e *eventGeneratorOperator) Init(globalParams *params.Params) error {
	e.enabled = globalParams.Get(ParamEnable).AsBool()
	if !e.enabled {
		return nil
	}

	// TODO: Allow configuring the k8s-node environments from config. For
	// instance the pod-name, container name, namespace, kubelet's kubeconfig
	// location and the manifest path. Probably we want to create a environment
	// in the config and just use it from flags --event-generator-env=k8s-node,
	// where k8s-node is the name of the environment defined in the config.
	// if config.Config != nil {}
	e.allowedGenerators = globalParams.Get(ParamAllowedGenerators).AsStringSlice()
	e.allowedEnvironments = globalParams.Get(ParamAllowedEnvironments).AsStringSlice()
	return nil
}

func (e *eventGeneratorOperator) InstanceParams() api.Params {
	return nil
}

func (e *eventGeneratorOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if !e.enabled {
		gadgetCtx.Logger().Debugf("event generator operator is disabled, skipping instantiation")
		return nil, nil
	}
	if len(e.allowedGenerators) == 0 {
		gadgetCtx.Logger().Debugf("event generator operator has no allowed generators configured, skipping instantiation")
		return nil, nil
	}
	if len(e.allowedEnvironments) == 0 {
		gadgetCtx.Logger().Debugf("event generator operator has no allowed environments configured, skipping instantiation")
		return nil, nil
	}

	gadgetCtx.Logger().Debugf("instantiating event generator operator with allowed generators: %v and environments: %v",
		e.allowedGenerators, e.allowedEnvironments)

	cfg, ok := gadgetCtx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("missing configuration")
	}
	v, ok := cfg.(*viper.Viper)
	if !ok {
		return nil, fmt.Errorf("invalid configuration format")
	}

	// First, collect all tags with "event-generator-" prefix
	var eventGenTags []string
	for _, tag := range v.GetStringSlice("tags") {
		if strings.HasPrefix(tag, "event-generator-") {
			eventGenTags = append(eventGenTags, strings.TrimPrefix(tag, "event-generator-"))
		}
	}

	// Then, split into generators and environments
	var taggedGenerators []string
	var taggedEnvironments []string
	for _, tag := range eventGenTags {
		if strings.HasPrefix(tag, "environment-") {
			// e.g. "environment-host" -> "host"
			taggedEnvironments = append(taggedEnvironments, strings.TrimPrefix(tag, "environment-"))
		} else {
			// e.g. "dns"
			taggedGenerators = append(taggedGenerators, tag)
		}
	}

	if len(taggedGenerators) == 0 {
		gadgetCtx.Logger().Debugf("gadget is not compatible with any event generators, skipping instantiation")
		return nil, nil
	}
	if len(taggedEnvironments) == 0 {
		gadgetCtx.Logger().Debugf("gadget is not compatible with any event environments, skipping instantiation")
		return nil, nil
	}

	// Each gadget defines the generators and environments it is compatible with using tags
	eop := &eventGeneratorOperatorInstance{
		compatibleEnvironments: taggedEnvironments,
		compatibleGenerators:   taggedGenerators,
	}

	gadgetCtx.Logger().Debugf("event generator operator instance compatible with generators: %v and environments: %v",
		eop.compatibleGenerators, eop.compatibleEnvironments)

	if gen, ok := instanceParamValues[ParamType]; ok && gen != "" {
		gadgetCtx.Logger().Debugf("instantiating event generator operator instance with generator type %q", gen)

		// Is this generator globally allowed?
		if !slices.Contains(e.allowedGenerators, gen) {
			return nil, fmt.Errorf("event generator %q is not allowed (allowed generators: %v)", gen, e.allowedGenerators)
		}
		// Is compatible with the gadget?
		if !slices.Contains(eop.compatibleGenerators, gen) {
			return nil, fmt.Errorf("event generator %q is not compatible with this gadget (compatible generators: %v)", gen, eop.compatibleGenerators)
		}

		env, ok := instanceParamValues[ParamEnvironment]
		if ok && env != "" {
			// Is this environment globally allowed and compatible with the gadget?
			if !slices.Contains(e.allowedEnvironments, env) {
				return nil, fmt.Errorf("event environment %q is not allowed (allowed environments: %v)", env, e.allowedEnvironments)
			}
			if !slices.Contains(eop.compatibleEnvironments, env) {
				return nil, fmt.Errorf("event environment %q is not compatible with this gadget (compatible environments: %v)", env, eop.compatibleEnvironments)
			}
		} else {
			return nil, fmt.Errorf("event environment is required", ParamEnvironment)
		}

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

		gadgetCtx.Logger().Debugf("creating event generator of type %q with environment %q, count %d, interval %s and params %v",
			gen, env, count, interval, gparams)
		eop.generator, err = generators.New(
			gen,
			gadgetCtx.Logger(),
			env,
			count,
			interval,
			gparams,
		)
		if err != nil {
			return nil, fmt.Errorf("creating event generator of type %q: %w", gen, err)
		}
	}

	return eop, nil
}

func (e *eventGeneratorOperator) Priority() int {
	return priority
}

type eventGeneratorOperatorInstance struct {
	generator              generators.Generator
	compatibleGenerators   []string
	compatibleEnvironments []string
}

func (e *eventGeneratorOperatorInstance) Name() string {
	return name
}

func (e *eventGeneratorOperatorInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	return api.Params{
		{
			Key:            ParamType,
			Description:    "Event Generator Type",
			TypeHint:       api.TypeStringSlice,
			PossibleValues: e.compatibleGenerators,
		},
		{
			Key:            ParamEnvironment,
			Description:    "Environment where the generator will run",
			TypeHint:       api.TypeStringSlice,
			DefaultValue:   generators.EnvHost.String(),
			PossibleValues: e.compatibleEnvironments,
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
			Key:         ParamParams,
			Description: "Comma-separated list of key-value pairs for a generator",
			TypeHint:    api.TypeString,
		},
	}
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
