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
	"errors"
	"fmt"
	"sort"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (c *GadgetContext) initAndPrepareOperators(paramValues api.ParamValues) error {
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

	c.dataOperatorInstances = make([]operators.DataOperatorInstance, 0, len(ops))
	for _, op := range ops {
		log.Debugf("initializing data op %q", op.Name())
		opParamPrefix := fmt.Sprintf("operator.%s", op.Name())

		// Get and fill params
		globalParams := op.GlobalParams().AddPrefix(opParamPrefix)
		instanceParams := op.InstanceParams().AddPrefix(opParamPrefix)
		opParamValues := paramValues.ExtractPrefixedValues(opParamPrefix)

		err := apihelpers.Validate(globalParams, opParamValues)
		if err != nil {
			return fmt.Errorf("validating global params for operator %q: %w", op.Name(), err)
		}

		err = apihelpers.Validate(instanceParams, opParamValues)
		if err != nil {
			return fmt.Errorf("validating instance params for operator %q: %w", op.Name(), err)
		}

		opInst, err := op.InstantiateDataOperator(c, opParamValues)
		if err != nil {
			return fmt.Errorf("instantiating operator %q: %w", op.Name(), err)
		}
		if opInst == nil {
			log.Debugf("> skipped %s", op.Name())
			continue
		}
		c.dataOperatorInstances = append(c.dataOperatorInstances, opInst)

		// Add instance params only if operator was actually instantiated (i.e., activated)
		params = append(params, instanceParams...)
	}

	for _, opInst := range c.dataOperatorInstances {
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

	return nil
}

func (c *GadgetContext) preStart() error {
	var errs []error

	for _, opInst := range c.dataOperatorInstances {
		if preStart, ok := opInst.(operators.PreStart); ok {
			c.Logger().Debugf("pre-starting op %q", opInst.Name())
			err := preStart.PreStart(c)
			if err != nil {
				errs = append(errs, fmt.Errorf("pre-starting operator %q: %w", opInst.Name(), err))
			}
		}
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) start() error {
	var errs []error

	for _, opInst := range c.dataOperatorInstances {
		c.Logger().Debugf("starting op %q", opInst.Name())
		err := opInst.Start(c)
		if err != nil {

			errs = append(errs, fmt.Errorf("starting operator %q: %w", opInst.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) stop() error {
	var errs []error

	// Stop in reverse order
	for i := len(c.dataOperatorInstances) - 1; i >= 0; i-- {
		opInst := c.dataOperatorInstances[i]
		c.Logger().Debugf("stopping op %q", opInst.Name())
		err := opInst.Stop(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("stopping operator %q: %w", opInst.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) postStop() error {
	var errs []error

	// PostStop in reverse order
	for i := len(c.dataOperatorInstances) - 1; i >= 0; i-- {
		opInst := c.dataOperatorInstances[i]
		if postStop, ok := opInst.(operators.PostStop); ok {
			c.Logger().Debugf("post-stopping op %q", opInst.Name())
			err := postStop.PostStop(c)
			if err != nil {
				errs = append(errs, fmt.Errorf("post-stopping operator %q: %w", opInst.Name(), err))
			}
		}
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) close() error {
	var errs []error

	// Close in reverse order
	for i := len(c.dataOperatorInstances) - 1; i >= 0; i-- {
		opInst := c.dataOperatorInstances[i]
		c.Logger().Debugf("closing op %q", opInst.Name())
		if err := opInst.Close(c); err != nil {
			errs = append(errs, fmt.Errorf("closing operator %q: %w", opInst.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) PrepareGadgetInfo(paramValues api.ParamValues) error {
	err := c.initAndPrepareOperators(paramValues)
	c.close()
	return err
}

func (c *GadgetContext) Run(paramValues api.ParamValues) error {
	var errs []error

	defer c.cancel()
	defer c.close()

	err := c.initAndPrepareOperators(paramValues)
	if err != nil {
		return fmt.Errorf("initializing and preparing operators: %w", err)
	}

	if err := c.preStart(); err != nil {
		errs = append(errs, fmt.Errorf("pre-starting operators: %w", err))
	}

	if err := c.start(); err != nil {
		errs = append(errs, fmt.Errorf("starting operators: %w", err))
	}

	// TODO: should it return here?
	//if len(errs) > 0 {
	//	return errors.Join(errs...)
	//}

	c.Logger().Debugf("running...")
	WaitForTimeoutOrDone(c)

	if err := c.stop(); err != nil {
		errs = append(errs, fmt.Errorf("stopping operators: %w", err))
	}
	if err := c.postStop(); err != nil {
		errs = append(errs, fmt.Errorf("post-stopping operators: %w", err))
	}

	return errors.Join(errs...)
}
