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

package gadgetcontext

import (
	"context"
	"fmt"
	"sort"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (c *GadgetContext) initAndPrepareOperators(paramValues api.ParamValues) ([]operators.DataOperatorInstance, error) {
	log := c.Logger()

	ops := c.DataOperators()

	// Sort dataOperators based on their priority
	sort.Slice(ops, func(i, j int) bool {
		return ops[i].Priority() < ops[j].Priority()
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
		globalParams := op.GlobalParams().AddPrefix(opParamPrefix)
		instanceParams := op.InstanceParams().AddPrefix(opParamPrefix)
		opParamValues := paramValues.ExtractPrefixedValues(opParamPrefix)

		err := apihelpers.Validate(globalParams, opParamValues)
		if err != nil {
			return nil, fmt.Errorf("validating global params for operator %q: %w", op.Name(), err)
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

func (c *GadgetContext) run(dataOperatorInstances []operators.DataOperatorInstance) error {
	defer c.cancel()
	log := c.Logger()

	for _, opInst := range dataOperatorInstances {
		preStart, ok := opInst.(operators.PreStart)
		if !ok {
			continue
		}
		log.Debugf("pre-starting op %q", opInst.Name())
		err := preStart.PreStart(c)
		if err != nil {
			c.cancel()
			return fmt.Errorf("pre-starting operator %q: %w", opInst.Name(), err)
		}
	}

	ctx := c.Context()
	if c.timeout > 0 {
		newContext, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		ctx = newContext
	}

	for _, opInst := range dataOperatorInstances {
		log.Debugf("starting op %q", opInst.Name())
		err := opInst.Start(c)
		if err != nil {
			c.cancel()
			return fmt.Errorf("starting operator %q: %w", opInst.Name(), err)
		}
	}

	log.Debugf("running...")

	<-ctx.Done()

	// Stop/DeInit in reverse order
	for i := len(dataOperatorInstances) - 1; i >= 0; i-- {
		opInst := dataOperatorInstances[i]
		log.Debugf("stopping op %q", opInst.Name())
		err := opInst.Stop(c)
		if err != nil {
			log.Errorf("stopping operator %q: %v", opInst.Name(), err)
		}
	}

	// Stop/DeInit in reverse order
	for i := len(dataOperatorInstances) - 1; i >= 0; i-- {
		opInst := dataOperatorInstances[i]
		postStop, ok := opInst.(operators.PostStop)
		if !ok {
			continue
		}
		log.Debugf("post-stopping op %q", opInst.Name())
		err := postStop.PostStop(c)
		if err != nil {
			log.Errorf("post-stopping operator %q: %v", opInst.Name(), err)
		}
	}
	return nil
}

func (c *GadgetContext) PrepareGadgetInfo(paramValues api.ParamValues) error {
	_, err := c.initAndPrepareOperators(paramValues)
	return err
}

func (c *GadgetContext) Run(paramValues api.ParamValues) error {
	dataOperatorInstances, err := c.initAndPrepareOperators(paramValues)
	if err != nil {
		c.cancel()
		return fmt.Errorf("initializing and preparing operators: %w", err)
	}
	return c.run(dataOperatorInstances)
}
