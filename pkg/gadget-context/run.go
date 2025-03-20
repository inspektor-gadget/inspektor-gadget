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

package gadgetcontext

import (
	"fmt"
	"sort"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (c *GadgetContext) initAndPrepareOperators(paramValues api.ParamValues) ([]operators.DataOperatorInstance, error) {
	log := c.Logger()

	ops := c.DataOperators()

	// Sort dataOperators based on their priority and name
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Priority() != ops[j].Priority() {
			return ops[i].Priority() < ops[j].Priority()
		}
		return ops[i].Name() < ops[j].Name()
	})

	for _, op := range ops {
		log.Debugf("operator %q has priority %d", op.Name(), op.Priority())
	}

	params := make([]*api.Param, 0)

	dataOperatorInstances := make([]operators.DataOperatorInstance, 0, len(ops))
	for _, op := range ops {
		log.Debugf("initializing data op %q", op.Name())
		opParamPrefix := fmt.Sprintf("operator.%s", op.Name())

		// Get and fill params
		instanceParams := op.InstanceParams().AddPrefix(opParamPrefix)
		opParamValues := paramValues.ExtractPrefixedValues(opParamPrefix)

		// Ensure all params are present
		err := apihelpers.NormalizeWithDefaults(instanceParams, opParamValues)
		if err != nil {
			return nil, fmt.Errorf("normalizing instance params for operator %q: %w", op.Name(), err)
		}

		err = apihelpers.Validate(instanceParams, opParamValues)
		if err != nil {
			return nil, fmt.Errorf("validating instance params for operator %q: %w", op.Name(), err)
		}

		opInst, err := op.InstantiateDataOperator(c, opParamValues)
		if err != nil {
			return nil, fmt.Errorf("instantiating operator %q: %w", op.Name(), err)
		}
		if opInst == nil {
			log.Debugf("> skipped %s", op.Name())
			continue
		}
		dataOperatorInstances = append(dataOperatorInstances, opInst)

		// Add instance params only if operator was actually instantiated (i.e., activated)
		params = append(params, instanceParams...)
	}

	for _, opInst := range dataOperatorInstances {
		log.Debugf("preparing op %q", opInst.Name())
		opParamPrefix := fmt.Sprintf("operator.%s", opInst.Name())

		// Second pass params; this time the operator had the chance to prepare itself based on DataSources, etc.
		// this mainly is postponed to read default values that might differ from before; this second pass is
		// what is handed over to the remote end
		if extra, ok := opInst.(operators.DataOperatorExtraParams); ok {
			pd := extra.ExtraParams(c)
			params = append(params, pd.AddPrefix(opParamPrefix)...)
		}
	}

	c.SetParams(params)

	return dataOperatorInstances, nil
}

func (c *GadgetContext) start(dataOperatorInstances []operators.DataOperatorInstance) error {
	for _, opInst := range dataOperatorInstances {
		preStart, ok := opInst.(operators.PreStart)
		if !ok {
			continue
		}
		c.Logger().Debugf("pre-starting op %q", opInst.Name())
		err := preStart.PreStart(c)
		if err != nil {
			c.cancel()
			return fmt.Errorf("pre-starting operator %q: %w", opInst.Name(), err)
		}
	}
	for _, opInst := range dataOperatorInstances {
		c.Logger().Debugf("starting op %q", opInst.Name())
		err := opInst.Start(c)
		if err != nil {
			c.cancel()
			return fmt.Errorf("starting operator %q: %w", opInst.Name(), err)
		}
	}
	return nil
}

func (c *GadgetContext) stop(dataOperatorInstances []operators.DataOperatorInstance) {
	// Stop/DeInit in reverse order
	for i := len(dataOperatorInstances) - 1; i >= 0; i-- {
		opInst := dataOperatorInstances[i]
		preStop, ok := opInst.(operators.PreStop)
		if !ok {
			continue
		}
		c.Logger().Debugf("pre-stopping op %q", opInst.Name())
		err := preStop.PreStop(c)
		if err != nil {
			c.Logger().Errorf("pre-stopping operator %q: %v", opInst.Name(), err)
		}
	}
	for i := len(dataOperatorInstances) - 1; i >= 0; i-- {
		opInst := dataOperatorInstances[i]
		c.Logger().Debugf("stopping op %q", opInst.Name())
		err := opInst.Stop(c)
		if err != nil {
			c.Logger().Errorf("stopping operator %q: %v", opInst.Name(), err)
		}
	}
	for i := len(dataOperatorInstances) - 1; i >= 0; i-- {
		opInst := dataOperatorInstances[i]
		postStop, ok := opInst.(operators.PostStop)
		if !ok {
			continue
		}
		c.Logger().Debugf("post-stopping op %q", opInst.Name())
		err := postStop.PostStop(c)
		if err != nil {
			c.Logger().Errorf("post-stopping operator %q: %v", opInst.Name(), err)
		}
	}
}

func (c *GadgetContext) PrepareGadgetInfo(paramValues api.ParamValues) error {
	_, err := c.initAndPrepareOperators(paramValues)
	return err
}

func (c *GadgetContext) Run(paramValues api.ParamValues) error {
	defer c.cancel()

	dataOperatorInstances, err := c.initAndPrepareOperators(paramValues)
	if err != nil {
		return fmt.Errorf("initializing and preparing operators: %w", err)
	}

	if err := c.start(dataOperatorInstances); err != nil {
		return fmt.Errorf("starting operators: %w", err)
	}

	c.Logger().Debugf("running...")

	WaitForTimeoutOrDone(c)
	c.stop(dataOperatorInstances)

	return nil
}
