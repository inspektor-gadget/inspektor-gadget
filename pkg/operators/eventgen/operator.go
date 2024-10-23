package eventgen

import (
	"fmt"
	"strconv"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type eventGenOperator struct{}

func (e eventGenOperator) Name() string {
	return name
}

func (e eventGenOperator) Init(params *params.Params) error {
	return nil
}

func (e eventGenOperator) GlobalParams() api.Params {
	return getGlobalParams()
}

func (e eventGenOperator) InstanceParams() api.Params {
	return getInstanceParams()
}

func (e eventGenOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	enable, exists := instanceParamValues[ParamEventGenEnable]
	eventType, _ := instanceParamValues[ParamEventGenType]
	paramsStr, _ := instanceParamValues[ParamEventGenParams]
	countVal, _ := instanceParamValues[ParamEventGenCount]
	intervalVal, _ := instanceParamValues[ParamEventGenInterval]

	// If enable parameter doesn't exist, return disabled instance without logging
	if !exists || enable != "true" {
		return &eventGenOperatorInstance{enable: false}, nil
	}

	if eventType == "" {
		return nil, fmt.Errorf("eventgen-type not specified")
	}

	// Parse count
	count := eventgenerator.InfiniteCount
	if countVal != "" {
		parsedCount, err := strconv.Atoi(countVal)
		if err != nil {
			count = eventgenerator.InfiniteCount
		} else {
			count = parsedCount
		}
	}

	// Parse interval
	interval := time.Second
	if intervalVal != "" {
		parsedInterval, err := time.ParseDuration(intervalVal)
		if err != nil {
			return nil, fmt.Errorf("invalid interval format: %w", err)
		}
		interval = parsedInterval
	}

	return &eventGenOperatorInstance{
		enable:    true,
		eventType: eventType,
		params:    ParseParams(paramsStr),
		count:     count,
		interval:  interval,
	}, nil
}

func (e eventGenOperator) Priority() int {
	return 0
}

type eventGenOperatorInstance struct {
	enable    bool
	eventType string
	params    map[string]string
	count     int
	interval  time.Duration
	generator eventgenerator.Generator
}

func (e *eventGenOperatorInstance) Name() string {
	return name
}

func (e *eventGenOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	if !e.enable {
		if e.eventType != "" {
			gadgetCtx.Logger().Info("Eventgen not enabled, skipping")
		}
		return nil
	}

	gadgetCtx.Logger().Debugf("Starting EventGen with type: %s, params: %v", e.eventType, e.params)

	var err error
	e.generator, err = eventgenerator.NewGenerator(e.eventType, gadgetCtx.Logger())
	if err != nil {
		return fmt.Errorf("creating generator: %w", err)
	}

	err = e.generator.Generate(e.params, e.count, e.interval)
	if err != nil {
		return fmt.Errorf("generating event: %w", err)
	}

	gadgetCtx.Logger().Debugf("Generated %s event successfully", e.eventType)
	return nil
}

func (e *eventGenOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	if e.generator != nil {
		_, err := e.generator.Cleanup()
		if err != nil {
			return fmt.Errorf("cleaning up event pod: %w", err)
		}
	}
	return nil
}

// EventGen is used to expose the eventgen operator
var EventGen = &eventGenOperator{}
