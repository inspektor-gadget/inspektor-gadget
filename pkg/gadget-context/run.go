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

	params := make([]*api.Param, 0)

	dataOperatorInstances := make([]operators.DataOperatorInstance, 0, len(ops))
	for _, op := range ops {
		log.Debugf("initializing data op %q", op.Name())
		opParamPrefix := fmt.Sprintf("operator.%s", op.Name())

		// Lazily initialize operator
		// TODO: global params should be filled out from a config file or such; maybe it's a better idea not to
		// lazily initialize operators at all, but just hand over the config. The "lazy" stuff could then be done
		// if the operator is instantiated and needs to do work
		err := op.Init(apihelpers.ToParamDescs(op.GlobalParams()).ToParams())
		if err != nil {
			return nil, fmt.Errorf("initializing operator %q: %w", op.Name(), err)
		}

		// Get and fill params
		instanceParams := op.InstanceParams().AddPrefix(opParamPrefix)
		opParamValues := paramValues.ExtractPrefixedValues(opParamPrefix)

		params = append(params, instanceParams...)

		err = apihelpers.Validate(instanceParams, opParamValues)
		if err != nil {
			return nil, fmt.Errorf("validating params for operator %q: %w", op.Name(), err)
		}

		opInst, err := op.InstantiateDataOperator(c, opParamValues)
		if err != nil {
			log.Errorf("instantiating operator %q: %v", op.Name(), err)
		}
		if opInst == nil {
			log.Debugf("> skipped %s", op.Name())
			continue
		}
		dataOperatorInstances = append(dataOperatorInstances, opInst)
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

	for _, opInst := range dataOperatorInstances {
		log.Debugf("starting op %q", opInst.Name())
		err := opInst.Start(c)
		if err != nil {
			c.cancel()
			return fmt.Errorf("starting operator %q: %w", opInst.Name(), err)
		}
	}

	log.Debugf("running...")

	<-c.Context().Done()

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
