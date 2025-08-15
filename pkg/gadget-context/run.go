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
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/spf13/viper"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/metrics"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (c *GadgetContext) instantiateOperators(paramValues api.ParamValues) error {
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

	c.localOperators = make([]operators.DataOperatorInstance, 0, len(ops))
	for _, op := range ops {
		log.Debugf("initializing data op %q", op.Name())
		opParamPrefix := fmt.Sprintf("operator.%s", op.Name())

		// Get and fill params
		instanceParams := op.InstanceParams().AddPrefix(opParamPrefix)
		opParamValues := paramValues.ExtractPrefixedValues(opParamPrefix)

		// Ensure all params are present
		err := apihelpers.NormalizeWithDefaults(instanceParams, opParamValues)
		if err != nil {
			return fmt.Errorf("normalizing instance params for operator %q: %w", op.Name(), err)
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
		c.localOperators = append(c.localOperators, opInst)

		// Add instance params only if operator was actually instantiated (i.e., activated)
		params = append(params, instanceParams...)
	}

	for _, opInst := range c.localOperators {
		log.Debugf("preparing op %q", opInst.Name())
		opParamPrefix := fmt.Sprintf("operator.%s", opInst.Name())

		// Second pass params; this time the operator had the chance to prepare itself based on DataSources, etc.
		// this mainly is postponed to read default values that might differ from before; this second pass is
		// what is handed over to the remote end
		if extra, ok := opInst.(operators.ExtraParams); ok {
			pd := extra.ExtraParams(c)
			params = append(params, pd.AddPrefix(opParamPrefix)...)
		}
	}

	// set defaults for params according to gadget's config
	if cfg, ok := c.GetVar("config"); ok {
		if v, ok := cfg.(*viper.Viper); ok {
			defaults := v.GetStringMapString("paramDefaults")
			for _, p := range params {
				fullName := p.Prefix + p.Key
				if val, ok := defaults[fullName]; ok {
					p.DefaultValue = val
				}
			}
		}
	}

	c.SetParams(params)

	return nil
}

func (c *GadgetContext) preStart() error {
	for _, opInst := range c.localOperators {
		if preStart, ok := opInst.(operators.PreStart); ok {
			c.Logger().Debugf("pre-starting op %q", opInst.Name())
			err := preStart.PreStart(c)
			if err != nil {
				return fmt.Errorf("pre-starting operator %q: %w", opInst.Name(), err)
			}
		}
	}
	return nil
}

func (c *GadgetContext) start() error {
	started := []operators.DataOperatorInstance{}

	for _, opInst := range c.localOperators {
		c.Logger().Debugf("starting op %q", opInst.Name())
		err := opInst.Start(c)
		if err != nil {
			// Stop all operators that were started to be sure they're able to
			// release resources there
			c.stopOperators(started)
			c.postStopOperators(started)
			return fmt.Errorf("starting operator %q: %w", opInst.Name(), err)
		}
		started = append(started, opInst)
	}
	return nil
}

func (c *GadgetContext) preStop() error {
	var errs []error

	// PreStop in reverse order
	for i := len(c.localOperators) - 1; i >= 0; i-- {
		opInst := c.localOperators[i]
		if preStop, ok := opInst.(operators.PreStop); ok {
			c.Logger().Debugf("pre-stopping op %q", opInst.Name())
			err := preStop.PreStop(c)
			if err != nil {
				errs = append(errs, fmt.Errorf("pre-stopping operator %q: %w", opInst.Name(), err))
			}
		}
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) stopOperators(ops []operators.DataOperatorInstance) error {
	var errs []error

	// Stop in reverse order
	for i := len(ops) - 1; i >= 0; i-- {
		opInst := ops[i]
		c.Logger().Debugf("stopping op %q", opInst.Name())
		errs = append(errs, opInst.Stop(c))
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) stop() error {
	return c.stopOperators(c.localOperators)
}

func (c *GadgetContext) postStopOperators(ops []operators.DataOperatorInstance) error {
	var errs []error

	// PostStop in reverse order
	for i := len(ops) - 1; i >= 0; i-- {
		opInst := ops[i]
		if postStop, ok := opInst.(operators.PostStop); ok {
			c.Logger().Debugf("post-stopping op %q", opInst.Name())
			errs = append(errs, postStop.PostStop(c))
		}
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) postStop() error {
	return c.postStopOperators(c.localOperators)
}

func (c *GadgetContext) close() error {
	var errs []error

	// Close in reverse order
	for i := len(c.localOperators) - 1; i >= 0; i-- {
		opInst := c.localOperators[i]
		c.Logger().Debugf("closing op %q", opInst.Name())
		if err := opInst.Close(c); err != nil {
			errs = append(errs, fmt.Errorf("closing operator %q: %w", opInst.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (c *GadgetContext) PrepareGadgetInfo(paramValues api.ParamValues) error {
	err := c.instantiateOperators(paramValues)
	if err := c.close(); err != nil {
		c.logger.Warn("error closing operators after preparing gadget info:", err)
	}
	return err
}

func (c *GadgetContext) Run(paramValues api.ParamValues) error {
	defer c.cancel()
	defer func() {
		if err := c.close(); err != nil {
			c.logger.Warn("error closing operators after run gadget:", err)
		}
	}()

	// keep a copy - currently only used for custom params in SetMetadata()
	c.paramValues = paramValues

	metricAttribs := attribute.NewSet(
		attribute.KeyValue{Key: "gadget_image", Value: attribute.StringValue(c.imageName)},
	)

	udCtrRunningGadgets.Add(context.Background(), 1, metric.WithAttributeSet(metricAttribs))
	defer udCtrRunningGadgets.Add(context.Background(), -1, metric.WithAttributeSet(metricAttribs))

	err := c.instantiateOperators(paramValues)
	if err != nil {
		return fmt.Errorf("initializing and preparing operators: %w", err)
	}

	if err := c.preStart(); err != nil {
		return fmt.Errorf("pre-starting operators: %w", err)
	}

	if err := c.start(); err != nil {
		return fmt.Errorf("starting operators: %w", err)
	}

	c.Logger().Debugf("running...")
	WaitForTimeoutOrDone(c)

	var errs []error

	if err := c.preStop(); err != nil {
		errs = append(errs, fmt.Errorf("pre-stopping operators: %w", err))
	}
	if err := c.stop(); err != nil {
		errs = append(errs, fmt.Errorf("stopping operators: %w", err))
	}
	if err := c.postStop(); err != nil {
		errs = append(errs, fmt.Errorf("post-stopping operators: %w", err))
	}

	return errors.Join(errs...)
}

var udCtrRunningGadgets, _ = metrics.Int64UpDownCounter("ig_gadgets_running",
	metric.WithDescription("Number of running gadgets"),
	metric.WithUnit("{instance}"),
)
